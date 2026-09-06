package lab

// TranscriptSettings exposes only the configuration required by transport-level
// observability. It intentionally does not expose the full engine configuration.
type TranscriptSettings struct {
	StateDir             string
	IncludeCommands      bool
	IncludeCommandOutput bool
	RedactSecrets        bool
	MaximumOutputBytes   int64
}

func (e *Engine) GetTranscriptSettings() TranscriptSettings {
	return TranscriptSettings{
		StateDir:             e.cfg.StateDir,
		IncludeCommands:      e.cfg.Logging.IncludeCommands,
		IncludeCommandOutput: e.cfg.Logging.IncludeCommandOutput,
		RedactSecrets:        e.cfg.Logging.RedactKnownSecretPatterns,
		MaximumOutputBytes:   e.cfg.Limits.MaximumOutputBytes,
	}
}
