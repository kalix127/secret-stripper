use ratatui::style::Color;
use std::sync::OnceLock;

// Palette derived from the project banner: warm gold "Secret", slate-blue
// "stripper", sage/teal clipboard, coral-red hand, cream paper.
const BRAND_GREEN_RAW: Color = Color::Rgb(82, 205, 128);
const BRAND_GOLD_RAW: Color = Color::Rgb(250, 205, 100);
const BRAND_SLATE_RAW: Color = Color::Rgb(122, 144, 168);
const BRAND_CORAL_RAW: Color = Color::Rgb(232, 96, 84);
const BRAND_CREAM_RAW: Color = Color::Rgb(240, 233, 218);
const HEADER_SEP_RAW: Color = Color::Rgb(110, 118, 134);
const SOFT_WHITE_RAW: Color = Color::Rgb(206, 209, 214);
const TEXT_DIM_RAW: Color = Color::Rgb(146, 154, 168);
const BORDER_RAW: Color = Color::Rgb(84, 94, 114);

// Respect https://no-color.org: when NO_COLOR is set in the environment to any
// non-empty value, every theme color resolves to Color::Reset so the terminal
// renders plain text. Modifiers (bold, reverse) still apply, so selection
// highlighting stays visible.
fn no_color() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var_os("NO_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    })
}

fn pick(c: Color) -> Color {
    if no_color() {
        Color::Reset
    } else {
        c
    }
}

pub fn brand_green() -> Color {
    pick(BRAND_GREEN_RAW)
}
pub fn brand_gold() -> Color {
    pick(BRAND_GOLD_RAW)
}
pub fn brand_slate() -> Color {
    pick(BRAND_SLATE_RAW)
}
pub fn brand_coral() -> Color {
    pick(BRAND_CORAL_RAW)
}
pub fn brand_cream() -> Color {
    pick(BRAND_CREAM_RAW)
}

pub fn header_app() -> Color {
    brand_green()
}
pub fn header_sep() -> Color {
    pick(HEADER_SEP_RAW)
}

pub fn accent() -> Color {
    brand_green()
}
pub fn select_arrow() -> Color {
    brand_green()
}

pub fn icon_blue() -> Color {
    brand_slate()
}
pub fn icon_magenta() -> Color {
    brand_coral()
}
pub fn icon_yellow() -> Color {
    brand_gold()
}
pub fn icon_green() -> Color {
    brand_green()
}

pub fn soft_white() -> Color {
    pick(SOFT_WHITE_RAW)
}
pub fn text() -> Color {
    brand_cream()
}
pub fn text_dim() -> Color {
    pick(TEXT_DIM_RAW)
}
pub fn border() -> Color {
    pick(BORDER_RAW)
}
pub fn success() -> Color {
    brand_green()
}
pub fn warn() -> Color {
    brand_coral()
}
