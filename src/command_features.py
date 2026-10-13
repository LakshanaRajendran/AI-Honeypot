def extract_command_features(session_df):
	discovery_keywords = [
		"whoami",
		"uname",
		"hostname",
		"pwd",
		"ls",
		"ifconfig",
		"ip addr",
		"ps",
		"id",
	]
	file_keywords = [
		"cat",
		"less",
		"more",
		"head",
		"tail",
		"touch",
		"rm",
		"cp",
		"mv",
	]
	network_keywords = ["curl", "wget", "nc", "netstat", "ss"]
	execution_keywords = ["chmod", "bash", "sh", "python", "python3"]

	commands = (
		session_df["command"].fillna("").astype(str).str.strip().str.lower()
	)

	command_count = len(commands)
	unique_command_count = commands.nunique()

	def count_matches(keywords):
		count = 0
		for command in commands:
			if any(keyword in command for keyword in keywords):
				count += 1
		return count

	discovery_count = count_matches(discovery_keywords)
	file_count = count_matches(file_keywords)
	network_count = count_matches(network_keywords)
	execution_count = count_matches(execution_keywords)

	return {
		"command_count": command_count,
		"unique_command_count": unique_command_count,
		"discovery_command_count": discovery_count,
		"file_command_count": file_count,
		"network_command_count": network_count,
		"execution_command_count": execution_count,
	}


if __name__ == "__main__":
	import json
	from normalizer import normalize_events
	with open("../data/dummy/telemetry.json", "r", encoding="utf-8") as file:
		events = json.load(file)
	df = normalize_events(events)
	for sid, s in df.groupby("session"):
		print(sid, extract_command_features(s))
