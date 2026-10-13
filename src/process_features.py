def extract_process_features(session_df):
	processes = session_df["process"].fillna("").astype(str).str.lower()
	process_count = len(processes)
	unique_process_count = processes.nunique()
	process_switches = 0
	for i in range(1, len(processes)):
		if processes.iloc[i] != processes.iloc[i - 1]:
			process_switches += 1
	if process_count > 1:
		process_switch_rate = process_switches / (process_count - 1)
	else:
		process_switch_rate = 0.0
	return {
		"process_count": process_count,
		"unique_process_count": unique_process_count,
		"process_switch_count": process_switches,
		"process_switch_rate": process_switch_rate,
	}


if __name__ == "__main__":
	import json
	from normalizer import normalize_events
	with open("../data/dummy/telemetry.json", "r", encoding="utf-8") as file:
		events = json.load(file)
	df = normalize_events(events)
	for sid, s in df.groupby("session"):
		print(sid, extract_process_features(s))
