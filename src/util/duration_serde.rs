pub mod duration_seconds {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub fn serialize<S: Serializer>(
        duration: &TimeDelta,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        duration.num_seconds().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<TimeDelta, D::Error> {
        let secs = i64::deserialize(deserializer)?;
        TimeDelta::try_seconds(secs).ok_or_else(|| Error::custom("duration out of range"))
    }
}

pub mod duration_seconds_option {
    use chrono::TimeDelta;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub fn serialize<S: Serializer>(
        duration: &Option<TimeDelta>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        duration.map(|d| d.num_seconds()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TimeDelta>, D::Error> {
        let secs = Option::<i64>::deserialize(deserializer)?;
        secs.map(|secs| {
            TimeDelta::try_seconds(secs).ok_or_else(|| Error::custom("duration out of range"))
        })
        .transpose()
    }
}
