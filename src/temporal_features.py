def extract_temporal_features(session_df):
	timestamps = session_df["timestamp"]
	event_count = len(session_df)
	if event_count > 1:
		intervals = timestamps.diff().dt.total_seconds().dropna()
		mean_inter_event_time = intervals.mean()
		median_inter_event_time = intervals.median()
		std_inter_event_time = intervals.std()
	else:
		mean_inter_event_time = 0.0
		median_inter_event_time = 0.0
		std_inter_event_time = 0.0
	session_duration = (timestamps.iloc[-1] - timestamps.iloc[0]).total_seconds()
	event_rate = event_count / session_duration if session_duration > 0 else 0.0
	return {
		"event_count": event_count,
		"session_duration": session_duration,
		"event_rate": event_rate,
		"mean_inter_event_time": mean_inter_event_time,
		"median_inter_event_time": median_inter_event_time,
		"std_inter_event_time": std_inter_event_time,
	}


if __name__ == "__main__":
	import json
	from normalizer import normalize_events
	with open("../data/dummy/telemetry.json", "r", encoding="utf-8") as file:
		events = json.load(file)
	df = normalize_events(events)
	sessions = df.groupby("session")
	for sid, s in sessions:
		print(sid, extract_temporal_features(s))
