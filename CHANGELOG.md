# Changelog

## 1.0.9

### Fixed

- Fixed Code Insight response parsing for structured `{summary, description}` responses.
- Kept compatibility with the previous base64-encoded response format.

## 1.0.8

### Added

- Added support for configuration via the IDA Pro plugin manager (kevinmuoz).

## 1.0.7

### Fixed

- Improved error handling, now CodeInsight works with other CPU architectures identified by IDA Pro.

## 1.0.6

### Added

- Updated plugin metadata to support HCLI Plugin Manager ecosystem.

## 1.0.5

### Fixed

- Fixes crash when Code Insight returns an invalid response.

## 1.0.4

### Fixed

- Fixes issue that left IDA hanging while a query was being performed.

## 1.0.3

### Fixed

- BUG fixed (wrongly showing an invalid api key msg).

## 1.0.2

### Added

- Added support for IDA Pro 9.2.

## 1.0.0

### Added

- Added the Code Insight panel.

## 0.11

### Added

- Added support for IDA Pro 8.x.

## 0.10

- Initial release.