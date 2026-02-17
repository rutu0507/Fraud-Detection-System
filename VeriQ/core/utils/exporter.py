import csv

def export_csv(rows, file="veriq_logs.csv"):
    with open(file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Input","Result","Confidence","Time"])
        for r in rows:
            writer.writerow(r)
