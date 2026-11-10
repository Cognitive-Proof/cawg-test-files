//! Unsigned source media. Every asset is generated procedurally so the repository has no
//! third-party content.

use image::{Rgb, RgbImage};

pub const W: u32 = 640;
pub const H: u32 = 480;

/// Small deterministic PRNG so regenerated files are byte-stable apart from signatures.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> f32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 40) as f32 / (1u64 << 24) as f32
    }
}

fn clamp(v: f32) -> u8 {
    v.clamp(0.0, 255.0) as u8
}

/// Sky, horizon and sensor noise: stands in for a camera capture.
pub fn photo(seed: u64) -> RgbImage {
    let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let horizon = H as f32 * (0.5 + 0.04 * (seed % 5) as f32);
    let phase = seed as f32 * 0.9;
    RgbImage::from_fn(W, H, |x, y| {
        let n = (rng.next() - 0.5) * 22.0;
        let yf = y as f32;
        let hill = horizon - 30.0 * ((x as f32) / 90.0 + phase).sin();
        if yf < hill {
            let t = yf / hill;
            Rgb([clamp(90.0 + 80.0 * t + n), clamp(140.0 + 60.0 * t + n), clamp(220.0 - 20.0 * t + n)])
        } else {
            let t = (yf - hill) / (H as f32 - hill);
            Rgb([clamp(70.0 - 30.0 * t + n), clamp(110.0 - 40.0 * t + n), clamp(50.0 - 20.0 * t + n)])
        }
    })
}

/// Centre crop to 75%, the edit the `c2pa.opened` + `c2pa.cropped` cases record.
pub fn crop(img: &RgbImage) -> RgbImage {
    let (w, h) = (img.width() * 3 / 4, img.height() * 3 / 4);
    image::imageops::crop_imm(img, (img.width() - w) / 2, (img.height() - h) / 2, w, h).to_image()
}
