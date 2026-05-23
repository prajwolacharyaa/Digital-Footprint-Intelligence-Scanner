def calculate_threat(breaches):
    return min(len(breaches) * 25, 100)