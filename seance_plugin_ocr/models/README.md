# Embedded OCR models

These two [rten](https://github.com/robertknight/rten) neural-network models are
compiled into the `seance_plugin_ocr` binary via `include_bytes!`, so OCR runs
fully in-process with no external `tesseract` binary and no native library. They
are the models published by the [ocrs](https://github.com/robertknight/ocrs)
project.

| File                     | Role                              |
| ------------------------ | --------------------------------- |
| `text-detection.rten`    | Locates word bounding boxes       |
| `text-recognition.rten`  | Reads characters within each line |

## Provenance and integrity (SHA-256)

```
f15cfb56bd02c4bf478a20343986504a1f01e1665c2b3a0ad66340f054b1b5ca  text-detection.rten
e484866d4cce403175bd8d00b128feb08ab42e208de30e42cd9889d8f1735a6e  text-recognition.rten
```

Verify with `shasum -a 256 *.rten`.

The download address these files came from, an `ocrs-models` S3 bucket, now answers 403 Forbidden,
including for the `ocrs` command line tool. The models on
[Hugging Face](https://huggingface.co/robertknight/ocrs) are different files and produce wrong
text with the pinned `ocrs` and `rten` versions, so they are not a substitute. These two files are
therefore the only copy of the models this code is tested against.

## Licence

The `ocrs` code is Apache-2.0 or MIT. The models are not covered by that grant. The Hugging Face
model card states CC-BY-SA 4.0, and the `ocrs-models` README says the models are trained on
HierText, which is CC-BY-SA 4.0. Treat these two files as CC-BY-SA 4.0: a distributed binary
carries them, so it must keep the attribution and the share-alike terms for the models.
[NOTICE.md](../../NOTICE.md) records this. Whether the same terms apply to the exact files
here, which predate the Hugging Face upload, has not been confirmed with the author.

## Updating

Replace both files only with models that pass `cargo test -p seance_plugin_ocr` under the pinned
`ocrs` and `rten` versions, then update the digests above.
