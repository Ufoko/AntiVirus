from Detectors.hashCheck import SignatureDetector


detector = SignatureDetector()
malicious, reason = detector.scan("Samples/CleanFile.txt")  # or any test file
print("MALWARE DETECTED!" if malicious else "Clean", reason)


