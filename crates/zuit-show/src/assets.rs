//! Embedded static assets shipped with the binary.

/// `index.html`.
pub const INDEX_HTML: &[u8] = include_bytes!("../assets/index.html");
/// `app.js`.
pub const APP_JS: &[u8] = include_bytes!("../assets/app.js");
/// `styles.css`.
pub const STYLES_CSS: &[u8] = include_bytes!("../assets/styles.css");
/// `uplot.js`.
pub const UPLOT_JS: &[u8] = include_bytes!("../assets/uplot.js");
/// `uplot.min.css`.
pub const UPLOT_CSS: &[u8] = include_bytes!("../assets/uplot.min.css");
/// `fonts.css`.
pub const FONTS_CSS: &[u8] = include_bytes!("../assets/fonts.css");
/// Inter 400.
pub const INTER_400: &[u8] = include_bytes!("../assets/fonts/inter-400.woff2");
/// Inter 500.
pub const INTER_500: &[u8] = include_bytes!("../assets/fonts/inter-500.woff2");
/// Inter 600.
pub const INTER_600: &[u8] = include_bytes!("../assets/fonts/inter-600.woff2");
/// `JetBrains Mono` 400.
pub const JBMONO_400: &[u8] = include_bytes!("../assets/fonts/jbmono-400.woff2");
