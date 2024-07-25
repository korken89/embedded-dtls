// TODO: docs

pub trait Instant: Copy {
    /// Add a duration of `s` seconds to an instant
    fn add_s(&self, s: u32) -> Self;

    /// Calculate a duration in microseconds between two instants
    fn sub_as_us(&self, rhs: &Self) -> u32;
}

pub trait Delay: Clone {
    type Instant: Instant;

    async fn delay_ms(&mut self, ms: u32);

    async fn delay_until(&mut self, instant: Self::Instant);

    fn now(&self) -> Self::Instant;
}

pub struct PrettyDuration {
    ticks_in_us: u32,
}

impl PrettyDuration {
    pub fn from_us(ticks_in_us: u32) -> Self {
        Self { ticks_in_us }
    }

    fn fmt_impl<T>(&self, format: impl FnOnce(f64, &'static str) -> T) -> T {
        const MICROS_IN_SEC: f64 = 1_000_000_f64;
        const MICROS_IN_MILLIS: f64 = 1_000_f64;
        let secs = self.ticks_in_us as f64 / MICROS_IN_SEC;
        if secs > 1.0 {
            return format(secs, "s");
        }
        let millis = self.ticks_in_us as f64 / MICROS_IN_MILLIS;
        if millis > 1.0 {
            return format(millis, "ms");
        }
        format(self.ticks_in_us as f64, "µs")
    }
}

#[cfg(feature = "log")]
impl core::fmt::Display for PrettyDuration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_impl(|v, unit| write!(f, "{} {}", v, unit))
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PrettyDuration {
    fn format(&self, f: defmt::Formatter) {
        self.fmt_impl(|v, unit| defmt::write!(f, "{} {}", v, unit))
    }
}

#[cfg(test)]
mod test {
    use crate::PrettyDuration;

    #[test]
    fn check_formatting_pretty_duration() {
        assert_eq!("10 s", PrettyDuration::from_us(10000000).to_string());
        assert_eq!("16.54321 s", PrettyDuration::from_us(16543210).to_string());
        assert_eq!("1.654321 s", PrettyDuration::from_us(1654321).to_string());
        assert_eq!("165.432 ms", PrettyDuration::from_us(165432).to_string());
        assert_eq!("16.543 ms", PrettyDuration::from_us(16543).to_string());
        assert_eq!("1.654 ms", PrettyDuration::from_us(1654).to_string());
        assert_eq!("165 µs", PrettyDuration::from_us(165).to_string());
        assert_eq!("0 µs", PrettyDuration::from_us(0).to_string());
    }
}
