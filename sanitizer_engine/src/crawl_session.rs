use crate::FetchedContent;
use crate::InputSource;
use crate::errors::RuleError;
use crate::errors::SanitizerError;
use crate::errors::SanitizerMessage;
use crate::html::CrawlerState;
use crate::html::create_rewriter;
use crate::http_client::SanitizerHttpClient;
use crate::log::ChannelLogger;
use crate::log::Log;
use crate::policy::Policy;
use crate::resources::mime;
use crate::resources::mime::KnownResourceType;
use crate::resources::strip_jpeg_metadata;
use crate::resources::strip_png_metadata;
use crate::resources::xml::XmlReader;
use crate::url::detect_idn;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;

/// Context tracking session progress, limits, and state for a single crawl/sanitization workflow.
pub struct CrawlSession {
    pub client: Arc<SanitizerHttpClient>,
    pub policy: Arc<Policy>,
    pub logger: ChannelLogger,
    pub rt_handle: tokio::runtime::Handle,
    pub output_dir: Arc<PathBuf>,
    pub url_map: Arc<Mutex<HashMap<Url, usize>>>,
    pub total_requests: Mutex<usize>,
    pub total_bytes: Mutex<usize>,
}

impl CrawlSession {
    pub fn new(
        client: Arc<SanitizerHttpClient>,
        policy: Arc<Policy>,
        logger: ChannelLogger,
        rt_handle: tokio::runtime::Handle,
        output_dir: Arc<PathBuf>,
        url_map: Arc<Mutex<HashMap<Url, usize>>>,
    ) -> Self {
        Self {
            client,
            policy,
            logger,
            rt_handle,
            output_dir,
            url_map,
            total_requests: Mutex::new(0),
            total_bytes: Mutex::new(0),
        }
    }

    fn index(&self) -> usize {
        self.logger.index
    }

    /// Worker task fetching and sanitizing a single sub-resource URL. Recursively enqueues nested resources (like inside CSS).
    async fn crawl_subresource(
        self: &Arc<Self>,
        url: Url,
        local_name: String,
        depth: usize,
        logger: &impl Log,
    ) -> Result<(), SanitizerError> {
        let total_bytes = *self.total_bytes.lock();

        self.policy
            .resources
            .max_bytes
            .check(total_bytes, &self.logger)?;

        logger.info(SanitizerMessage::CrawlingSubresource {
            depth,
            remote: InputSource::Url(url.clone()),
            local: local_name.clone(),
        });

        let FetchedContent { data, content_type } = self
            .client
            .fetch_raw(&url, logger, &self.policy, total_bytes)
            .await?;

        {
            let mut total_bytes = self.total_bytes.lock();
            *total_bytes += data.len();
        }

        let declared = content_type.as_deref().map(mime::clean);
        let sniffed = mime::sniff(&data).or_else(|| {
            url.path()
                .rsplit_once('.')
                .map(|(_, x)| x)
                .and_then(KnownResourceType::from_extension)
        });
        if !mime::validate(declared.as_deref(), sniffed) {
            let err = RuleError::MimeMismatch {
                expected: declared.clone(),
                actual: sniffed.map(|x| x.to_string()),
            };
            self.policy.resources.mismatched_mime.handle(logger, err)?;
        }

        let resource_type =
            sniffed.or_else(|| declared.as_deref().and_then(KnownResourceType::parse));

        let output = self.output_dir.join(&local_name);

        match resource_type {
            None => {
                self.policy
                    .resources
                    .unknown_resource
                    .handle(logger, RuleError::UnknownResourceType { mime: declared })?;

                fs::write(&output, &data).map_err(|e| SanitizerError::WriteFile(output, e))
            }
            Some(KnownResourceType::Png) => {
                let data = strip_png_metadata(&data);
                fs::write(&output, &data).map_err(|e| SanitizerError::WriteFile(output, e))
            }
            Some(KnownResourceType::Jpeg) => {
                let data = strip_jpeg_metadata(&data);
                fs::write(&output, &data).map_err(|e| SanitizerError::WriteFile(output, e))
            }
            Some(KnownResourceType::Gif | KnownResourceType::Webp) => {
                fs::write(&output, &data).map_err(|e| SanitizerError::WriteFile(output, e))
            }
            Some(KnownResourceType::Css) => {
                self.process_css_file(logger, depth, &url, &data, output)
            }
            Some(KnownResourceType::Js) => self.process_js_file(logger, &data, output),
            Some(KnownResourceType::Pdf) => self.process_pdf_file(logger, &data, output),
        }
    }

    /// Checks limits and registers a sub-resource URL, then enqueues it if valid and not visited.
    fn try_enqueue_subresource(self: &Arc<Self>, url: Url, local_name: String, depth: usize) {
        let max_requests = &self.policy.resources.max_requests;
        let logger = {
            let mut visited = self.url_map.lock();
            if visited.contains_key(&url) {
                return;
            }

            let mut total_requests = self.total_requests.lock();
            *total_requests += 1;
            if *total_requests > *max_requests.value.as_ref() {
                if let Err(e) = max_requests.check(*total_requests, &self.logger) {
                    self.logger.error(e);
                }

                return;
            }

            visited.insert(url.clone(), self.index());
            self.logger.subresource(*total_requests)
        };

        if let Err(e) = self.policy.resources.max_depth.check(depth, &self.logger) {
            logger.error(e);
            return;
        }

        let clone = Arc::clone(self);
        self.rt_handle.spawn(async move {
            if let Err(e) = clone
                .crawl_subresource(url, local_name, depth, &logger)
                .await
            {
                logger.error(e);
            } else {
                logger.info(SanitizerMessage::ResourceCompleted);
            }
        });
    }

    /// Worker task processing a local file (HTML, PDF, etc.). Parses HTML, rewrites links, scans PDFs, and enqueues referenced sub-resources.
    pub fn process_file(self: &Arc<Self>, path: PathBuf) -> Result<(), SanitizerError> {
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            "pdf" => {
                let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;
                let output = self.output_dir.join(format!("{}.pdf", self.index()));
                self.process_pdf_file(&self.logger, &data, output)
            }
            "css" => {
                let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;
                let output = self.output_dir.join(format!("{}.css", self.index()));
                self.process_css_file(
                    &self.logger,
                    0,
                    &Url::parse("https://localhost").unwrap(),
                    &data,
                    output,
                )
            }
            "js" => {
                let data = fs::read(&path).map_err(|e| SanitizerError::ReadFile(path, e))?;
                let output = self.output_dir.join(format!("{}.js", self.index()));
                self.process_js_file(&self.logger, &data, output)
            }
            _ => self.process_html_file(path),
        }
    }

    fn process_pdf_file(
        &self,
        logger: &impl Log,
        data: &[u8],
        output: PathBuf,
    ) -> Result<(), SanitizerError> {
        crate::resources::pdf::sanitize(data, logger, self.policy.resources.pdf_active_content)?;
        fs::write(&output, data).map_err(|e| SanitizerError::WriteFile(output, e))
    }

    fn process_css_file(
        self: &Arc<Self>,
        logger: &impl Log,
        depth: usize,
        base_url: &Url,
        data: &[u8],
        output: PathBuf,
    ) -> Result<(), SanitizerError> {
        let data = String::from_utf8_lossy(data);
        let (data, nested_urls) =
            crate::resources::css::sanitize(&data, base_url, logger, &self.policy)?;

        for (remote, local) in nested_urls {
            self.try_enqueue_subresource(remote, local, depth + 1);
        }

        fs::write(&output, data.as_bytes()).map_err(|e| SanitizerError::WriteFile(output, e))
    }

    fn process_js_file(
        &self,
        logger: &impl Log,
        data: &[u8],
        output: PathBuf,
    ) -> Result<(), SanitizerError> {
        let data = String::from_utf8_lossy(data);
        let data = crate::resources::javascript::sanitize(
            &data,
            logger,
            &self.policy.resources.dangerous_js,
        )?;

        fs::write(&output, data.as_bytes()).map_err(|e| SanitizerError::WriteFile(output, e))
    }

    fn process_html_file(self: &Arc<Self>, path: PathBuf) -> Result<(), SanitizerError> {
        let output_path = self.output_dir.join(format!("{}.html", self.index()));

        let input_file =
            File::open(&path).map_err(|e| SanitizerError::OpenFile(path.clone(), e))?;
        let mut reader = BufReader::new(input_file);
        let output_file = File::create(&output_path)
            .map_err(|e| SanitizerError::CreateFile(output_path.clone(), e))?;

        let mut crawler_state = {
            CrawlerState {
                base: Url::parse("https://localhost").unwrap(),
                subresources: Vec::new(),
            }
        };

        let mut rewriter =
            create_rewriter(&self.logger, &self.policy, &mut crawler_state, output_file);

        let mut xml_reader = XmlReader::new(0);

        let mut buffer = [0; 8192];
        loop {
            let n = reader
                .read(&mut buffer)
                .map_err(|e| SanitizerError::ReadFile(path.clone(), e))?;
            if n == 0 {
                break;
            }

            let to_write = xml_reader.next_chunk(&buffer[..n], &self.policy, &self.logger)?;

            // let _ = std::fs::remove_file(&output_path);
            rewriter.write(&to_write)?;
        }
        rewriter.end()?;

        for (sub_url, local_name) in crawler_state.subresources {
            self.try_enqueue_subresource(sub_url, local_name, 1);
        }

        Ok(())
    }

    /// Worker task fetching a remote HTML document, sanitizing it, and enqueuing referenced sub-resources.
    pub async fn process_url(self: &Arc<Self>, url: Url) -> Result<(), SanitizerError> {
        if let Some((original, replacement)) = detect_idn(&url) {
            self.policy.urls.idn_connection.handle(
                &self.logger,
                RuleError::IdnConnection {
                    original: original.to_owned(),
                    converted: replacement.to_owned(),
                },
            )?;
        }

        if let Some(host) = url.host().map(|x| x.to_owned()) {
            self.policy
                .connections
                .dangerous_domain
                .check((&host, &self.policy.urls.dangerous_domains), &self.logger)?;
        }

        let index = self.index();
        let output_path = self.output_dir.join(format!("{index}.html"));
        let fetch_result = self
            .client
            .fetch_and_sanitize_html(&url, &self.logger, &output_path, &self.policy)
            .await;

        let CrawlerState {
            base: final_base,
            subresources: discovered,
        } = fetch_result?;

        // Record the main HTML page request and visit
        {
            let mut visited = self.url_map.lock();
            visited.insert(url.clone(), index);
            visited.insert(final_base.clone(), index);
        }

        for (sub_url, local_name) in discovered {
            self.try_enqueue_subresource(sub_url, local_name, 1);
        }

        Ok(())
    }
}
