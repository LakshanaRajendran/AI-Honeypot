from reader import load_telemetry
from validator import validate_events
from cleaner import clean_events
from normalizer import normalize_events
from sessionizer import group_by_session
from feature_extractor import extract_features
from writer import save_json


def run_pipeline(input_file):
	# ----------------------------
	# STEP 1: READ
	# ----------------------------
	events = load_telemetry(input_file)
	print("Raw events:", len(events))

	# ----------------------------
	# STEP 2: VALIDATE
	# ----------------------------
	valid_events, invalid_events = validate_events(events)
	print("Valid events:", len(valid_events))
	print("Invalid events:", len(invalid_events))

	# ----------------------------
	# STEP 3: CLEAN
	# ----------------------------
	cleaned_events = clean_events(valid_events)
	print("Cleaned events:", len(cleaned_events))

	# ----------------------------
	# STEP 4: NORMALIZE
	# ----------------------------
	df = normalize_events(cleaned_events)
	print("DataFrame created:", df.shape)

	# ----------------------------
	# STEP 5: SESSIONIZE
	# ----------------------------
	sessions = group_by_session(df)
	print("Sessions:", len(sessions))

	# ----------------------------
	# STEP 6: FEATURE EXTRACTION
	# ----------------------------
	results = []
	for session_id, session_df in sessions.items():
		features = extract_features(session_df)
		results.append({"session": session_id, "features": features})
	return results


if __name__ == "__main__":
	input_file = "../data/dummy/telemetry.json"
	output_file = "../output/features/session_features.json"
	results = run_pipeline(input_file)
	save_json(results, output_file)
	print("\nFeature extraction completed.")
	print("Output:", output_file)
