def group_by_session(df):
	sessions = {}
	for session_id, session_df in df.groupby("session"):
		sessions[session_id] = session_df.sort_values("timestamp").reset_index(drop=True)
	return sessions


if __name__ == "__main__":
	import json
	from normalizer import normalize_events
	with open("../data/dummy/telemetry.json", "r", encoding="utf-8") as file:
		events = json.load(file)
	df = normalize_events(events)
	sessions = group_by_session(df)
	print("Sessions:", len(sessions))
