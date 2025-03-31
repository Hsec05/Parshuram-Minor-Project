from config.mongo_confing import collections

def store_other_logs(logs, type):
    """
    Stores multiple logs in the 'other_logs_collection'.
    
    :param logs: List of dictionaries, each containing log details.
    """
    if not isinstance(logs, list) or not all(isinstance(log, dict) for log in logs):
        raise ValueError("Logs must be a list of dictionaries")

    if logs:
        collections[f"{type}_other_logs"].insert_many(logs)
        print(f"{len(logs)} logs stored in 'other_logs_collection' successfully.")
