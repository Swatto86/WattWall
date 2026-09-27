//! The tray icon is drawn at run time: a small brick wall with two meter bars
//! beside it, red for bytes sent and green for bytes received, the way
//! ZoneAlarm's tray icon showed traffic. The wall turns grey while every
//! WattWall block is off, and red while Block All cuts every program off.
//!
//! The drawing is laid out on a 16 by 16 grid. Every edge is rounded to a
//! whole pixel at the size Windows asks for, so it stays sharp at 16, 20, 24
//! and 32 pixels.

use std::collections::HashMap;

/// What the tray icon shows. `sending` and `receiving` are filled pixels of
/// each bar, from 0 to [`Glyph::steps`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrayLook {
    pub paused: bool,
    /// Block All is on.
    pub locked: bool,
    pub sending: u32,
    pub receiving: u32,
}

/// Bricks on the 16 grid, as x0, y0, x1, y1: three courses in running bond.
const BRICKS: [[u32; 4]; 7] = [
    [0, 3, 5, 6],
    [6, 3, 10, 6],
    [0, 7, 2, 10],
    [3, 7, 7, 10],
    [8, 7, 10, 10],
    [0, 11, 5, 14],
    [6, 11, 10, 14],
];
const SEND_BAR: [u32; 2] = [11, 13];
const RECEIVE_BAR: [u32; 2] = [14, 16];
const BAR_TOP: u32 = 3;
const BAR_BOTTOM: u32 = 14;

const WALL_FROM: [u8; 3] = [0xFF, 0xA2, 0x3D];
const WALL_TO: [u8; 3] = [0xF0, 0x45, 0x2F];
const WALL_PAUSED: [u8; 3] = [0x9A, 0xA3, 0xAE];
const WALL_LOCKED: [u8; 3] = [0xE5, 0x38, 0x3B];
const SEND: [u8; 3] = [0xFF, 0x3B, 0x4E];
const RECEIVE: [u8; 3] = [0x2F, 0xD2, 0x7A];
/// The empty part of a bar: grey at 35%, visible on light and dark taskbars.
const TRACK: [u8; 4] = [0x8A, 0x8F, 0x98, 0x59];

/// Below this many bytes a second a bar stays empty.
const QUIET: f64 = 512.0;
/// The bar scale is logarithmic from 1 KB/s (one pixel) to 10 MB/s (full),
/// so light background traffic still shows.
const SCALE_LOW: f64 = 1024.0;
const SCALE_HIGH: f64 = 10.0 * 1024.0 * 1024.0;

/// The tray drawing at one pixel size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyph {
    size: u32,
}

impl Glyph {
    /// Sizes outside 16..=256 are clamped into that range.
    pub fn new(size: u32) -> Self {
        Self {
            size: size.clamp(16, 256),
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Height of a bar in pixels: how many levels it can show.
    pub fn steps(&self) -> u32 {
        self.at(BAR_BOTTOM) - self.at(BAR_TOP)
    }

    /// Square RGBA image, `size * size * 4` bytes, straight alpha.
    pub fn draw(&self, look: TrayLook) -> Vec<u8> {
        let size = self.size;
        let mut rgba = vec![0u8; (size * size * 4) as usize];
        let span = (2 * (size - 1)) as f32;
        for [x0, y0, x1, y1] in BRICKS {
            let area = [self.at(x0), self.at(y0), self.at(x1), self.at(y1)];
            self.fill(&mut rgba, area, |x, y| {
                let colour = if look.locked {
                    WALL_LOCKED
                } else if look.paused {
                    WALL_PAUSED
                } else {
                    mix(WALL_FROM, WALL_TO, (x + y) as f32 / span)
                };
                [colour[0], colour[1], colour[2], 0xFF]
            });
        }
        let (top, bottom) = (self.at(BAR_TOP), self.at(BAR_BOTTOM));
        let bars = [
            (SEND_BAR, look.sending, SEND),
            (RECEIVE_BAR, look.receiving, RECEIVE),
        ];
        for ([x0, x1], filled, colour) in bars {
            let (x0, x1) = (self.at(x0), self.at(x1));
            let level = bottom - filled.min(bottom - top);
            self.fill(&mut rgba, [x0, top, x1, level], |_, _| TRACK);
            self.fill(&mut rgba, [x0, level, x1, bottom], |_, _| {
                [colour[0], colour[1], colour[2], 0xFF]
            });
        }
        rgba
    }

    /// A 16-grid coordinate at this size, rounded to the nearest pixel edge.
    fn at(&self, grid: u32) -> u32 {
        (grid * self.size + 8) / 16
    }

    fn fill(
        &self,
        rgba: &mut [u8],
        [x0, y0, x1, y1]: [u32; 4],
        paint: impl Fn(u32, u32) -> [u8; 4],
    ) {
        for y in y0..y1.min(self.size) {
            for x in x0..x1.min(self.size) {
                let at = ((y * self.size + x) * 4) as usize;
                rgba[at..at + 4].copy_from_slice(&paint(x, y));
            }
        }
    }
}

fn mix(from: [u8; 3], to: [u8; 3], t: f32) -> [u8; 3] {
    let t = t.clamp(0.0, 1.0);
    let channel = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
    [
        channel(from[0], to[0]),
        channel(from[1], to[1]),
        channel(from[2], to[2]),
    ]
}

/// Filled pixels of a bar with `steps` levels for this many bytes a second.
pub fn meter_fill(bytes_per_second: f64, steps: u32) -> u32 {
    if steps == 0 || bytes_per_second.is_nan() || bytes_per_second < QUIET {
        return 0;
    }
    let low = SCALE_LOW.log10();
    let high = SCALE_HIGH.log10();
    let t = ((bytes_per_second.log10() - low) / (high - low)).clamp(0.0, 1.0);
    ((t * steps as f64).ceil() as u32).clamp(1, steps)
}

/// A rate for people: "0 B/s", "512 B/s", "1.5 KB/s", "12 MB/s".
pub fn rate_text(bytes_per_second: f64) -> String {
    const UNITS: [&str; 4] = ["B/s", "KB/s", "MB/s", "GB/s"];
    let mut value = if bytes_per_second.is_finite() && bytes_per_second > 0.0 {
        bytes_per_second
    } else {
        0.0
    };
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit > 0 && value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// Octet counters per network adapter (its LUID): received, then sent.
pub type Counters = HashMap<u64, (u64, u64)>;

/// Bytes received and sent between two readings. Only adapters present in
/// both count, and a counter that went backwards counts as zero, so an
/// adapter that appears or resets does not look like a burst of traffic.
pub fn traffic_between(before: &Counters, after: &Counters) -> (u64, u64) {
    let mut received = 0u64;
    let mut sent = 0u64;
    for (adapter, (now_in, now_out)) in after {
        if let Some((was_in, was_out)) = before.get(adapter) {
            received = received.saturating_add(now_in.saturating_sub(*was_in));
            sent = sent.saturating_add(now_out.saturating_sub(*was_out));
        }
    }
    (received, sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let at = ((y * size + x) * 4) as usize;
        [rgba[at], rgba[at + 1], rgba[at + 2], rgba[at + 3]]
    }

    #[test]
    fn draws_a_square_image_at_every_tray_size() {
        for size in [16, 20, 24, 32, 40, 48] {
            let glyph = Glyph::new(size);
            assert_eq!(
                glyph.draw(TrayLook::default()).len(),
                (size * size * 4) as usize
            );
            assert!(
                glyph.steps() >= 11,
                "{size} px bars need at least 11 levels"
            );
        }
        assert_eq!(Glyph::new(4).size(), 16);
        assert_eq!(Glyph::new(4000).size(), 256);
    }

    #[test]
    fn wall_is_orange_and_turns_grey_when_paused() {
        let glyph = Glyph::new(16);
        let on = glyph.draw(TrayLook::default());
        let brick = pixel(&on, 16, 1, 4);
        assert_eq!(brick[3], 0xFF);
        assert!(
            brick[0] > brick[1] && brick[1] > brick[2],
            "orange: {brick:?}"
        );
        let off = glyph.draw(TrayLook {
            paused: true,
            ..TrayLook::default()
        });
        assert_eq!(pixel(&off, 16, 1, 4), [0x9A, 0xA3, 0xAE, 0xFF]);
        let locked = glyph.draw(TrayLook {
            locked: true,
            paused: true,
            ..TrayLook::default()
        });
        assert_eq!(
            pixel(&locked, 16, 1, 4),
            [0xE5, 0x38, 0x3B, 0xFF],
            "Block All wins over paused"
        );
    }

    #[test]
    fn mortar_and_the_gap_before_the_bars_are_transparent() {
        let image = Glyph::new(16).draw(TrayLook::default());
        assert_eq!(pixel(&image, 16, 5, 4)[3], 0, "joint in the top course");
        assert_eq!(
            pixel(&image, 16, 3, 6)[3],
            0,
            "bed joint under the top course"
        );
        assert_eq!(pixel(&image, 16, 10, 8)[3], 0, "gap between wall and bars");
        assert_eq!(pixel(&image, 16, 13, 8)[3], 0, "gap between the bars");
    }

    #[test]
    fn bars_fill_from_the_bottom() {
        let glyph = Glyph::new(16);
        let steps = glyph.steps();
        let image = glyph.draw(TrayLook {
            paused: false,
            locked: false,
            sending: steps,
            receiving: 1,
        });
        assert_eq!(
            pixel(&image, 16, 11, 3),
            [0xFF, 0x3B, 0x4E, 0xFF],
            "full send bar"
        );
        assert_eq!(
            pixel(&image, 16, 14, 13),
            [0x2F, 0xD2, 0x7A, 0xFF],
            "one receive pixel"
        );
        assert_eq!(
            pixel(&image, 16, 14, 12),
            TRACK,
            "rest of the receive bar is track"
        );
        let over = glyph.draw(TrayLook {
            paused: false,
            locked: false,
            sending: steps + 50,
            receiving: 0,
        });
        assert_eq!(pixel(&over, 16, 11, 3), [0xFF, 0x3B, 0x4E, 0xFF]);
        assert_eq!(
            pixel(&over, 16, 11, 2)[3],
            0,
            "an overfull bar stays inside the icon"
        );
    }

    #[test]
    fn edges_stay_on_whole_pixels_at_twice_the_size() {
        let small = Glyph::new(16).draw(TrayLook::default());
        let large = Glyph::new(32).draw(TrayLook::default());
        for y in 0..16 {
            for x in 0..16 {
                let opaque = pixel(&small, 16, x, y)[3] == 0xFF;
                assert_eq!(
                    pixel(&large, 32, 2 * x, 2 * y)[3] == 0xFF,
                    opaque,
                    "({x},{y})"
                );
            }
        }
    }

    #[test]
    fn meter_scale() {
        assert_eq!(meter_fill(0.0, 11), 0);
        assert_eq!(meter_fill(100.0, 11), 0);
        assert_eq!(meter_fill(f64::NAN, 11), 0);
        assert_eq!(meter_fill(600.0, 11), 1, "just above quiet shows one pixel");
        assert_eq!(meter_fill(10.0 * 1024.0 * 1024.0, 11), 11);
        assert_eq!(meter_fill(1e12, 11), 11);
        assert_eq!(meter_fill(1e6, 0), 0);
        let mut last = 0;
        for exponent in 2..10 {
            let fill = meter_fill(10f64.powi(exponent), 11);
            assert!(fill >= last, "the bar never shrinks as traffic grows");
            last = fill;
        }
    }

    #[test]
    fn rate_text_is_short() {
        assert_eq!(rate_text(0.0), "0 B/s");
        assert_eq!(rate_text(-5.0), "0 B/s");
        assert_eq!(rate_text(512.0), "512 B/s");
        assert_eq!(rate_text(1536.0), "1.5 KB/s");
        assert_eq!(rate_text(12.0 * 1024.0 * 1024.0), "12 MB/s");
    }

    #[test]
    fn traffic_counts_only_adapters_seen_twice() {
        let before = Counters::from([(1, (1_000, 500)), (2, (9_000, 9_000))]);
        let after = Counters::from([
            (1, (1_600, 700)),
            (2, (10, 10)),
            (3, (5_000_000, 5_000_000)),
        ]);
        assert_eq!(traffic_between(&before, &after), (600, 200));
    }
}
