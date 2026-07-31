package output

import (
	"encoding/json"
	"fmt"
	"os"
)

func PrintJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON output: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func PrintError(jsonMode bool, errCode string, msg string) {
	if jsonMode {
		_ = PrintJSON(map[string]string{
			"error":   errCode,
			"message": msg,
		})
	} else {
		fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", errCode, msg)
	}
}
