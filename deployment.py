import pickle
import pandas as pd
import numpy as np

# Load the trained model
model_path = "/content/finalized_model.sav"
with open(model_path, 'rb') as model_file:
    clf = pickle.load(model_file)

# Load the label encoders
encoders_path = "/content/label_encoders.pkl"
with open(encoders_path, 'rb') as encoders_file:
    label_encoders = pickle.load(encoders_file)

# Function to classify input
def classify_input(input_data):
    # Convert input to DataFrame
    input_df = pd.DataFrame([input_data])

    # Ensure correct data types
    numeric_cols = ['Source_Port', 'Destination_Port']
    for col in numeric_cols:
        input_df[col] = pd.to_numeric(input_df[col], errors='coerce')  # Convert to numeric
    
    # Encode categorical columns
    for col in input_df.columns:
        if col in label_encoders:  # Apply encoding if column exists
            if input_df[col][0] in label_encoders[col].classes_:  # If seen before
                input_df[col] = label_encoders[col].transform([input_df[col][0]])
            else:  # Handle unseen categories
                print(f"Warning: Unseen category '{input_df[col][0]}' in column '{col}', replacing with 'Unknown'")
                unknown_label = 'Unknown'
                new_classes = np.append(label_encoders[col].classes_, unknown_label)
                label_encoders[col].classes_ = new_classes
                input_df[col] = label_encoders[col].transform([unknown_label])

    # Make prediction
    prediction = clf.predict(input_df)[0]

    # Interpret prediction
    label = "Attack" if prediction == 1 else "Normal"
    return label

#input
test_input = {
    'Source_Port': 7744,
    'Destination_Port': 2337,
    'Protocol': 'TCP',
    'Severity': 'High',
    'Category': 'Normal Traffic',
    'Classification': 'Malicious',
    'Status': 'Resolved',
    'Attack_Vector': 'None',  # This might be unseen
    'Affected_Assets': 'Mobile Device',
    'Operating_System': 'Fedora',
    'Network_Zone': 'Cloud',
    'Event_Type': 'Email Sent'
}

# Run prediction
print("Prediction:", classify_input(test_input))
