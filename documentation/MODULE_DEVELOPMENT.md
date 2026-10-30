# Module development

How to write a forensic module.

Creating a new forensic module:

```rust
use seance_core::{
    module::{ForensicsModule, InputCapability, ModuleError},
    artifact::{Artifact, ArtifactType},
    file_detection::{detect_file_type, DetectedFileType},
};

pub struct MyParser;

impl ForensicsModule for MyParser {
    fn id(&self) -> &str { "plugin.category.my_parser" }
    fn version(&self) -> &str { "0.1.0" }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        // Content-based detection (never rely on filenames alone)
        let detected = detect_file_type(data_source.as_ref());
        if detected != DetectedFileType::MyFormat {
            return Ok(Vec::new());
        }

        // Parse and produce child artifacts with .with_parent()
        let parsed = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({ "type": "MyRecord", /* ... */ }),
        ).with_parent(artifact.id);

        Ok(vec![parsed])
    }
}
```
