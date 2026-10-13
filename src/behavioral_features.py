def extract_behavioral_features(command_features):
	count = command_features["command_count"]
	if count == 0:
		return {
			"discovery_ratio": 0.0,
			"file_activity_ratio": 0.0,
			"network_activity_ratio": 0.0,
			"execution_ratio": 0.0,
		}
	return {
		"discovery_ratio": command_features["discovery_command_count"] / count,
		"file_activity_ratio": command_features["file_command_count"] / count,
		"network_activity_ratio": command_features["network_command_count"] / count,
		"execution_ratio": command_features["execution_command_count"] / count,
	}


if __name__ == "__main__":
	# Quick smoke test
	sample = {
		"command_count": 4,
		"discovery_command_count": 2,
		"file_command_count": 1,
		"network_command_count": 0,
		"execution_command_count": 1,
	}
	print(extract_behavioral_features(sample))
