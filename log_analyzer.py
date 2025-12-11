import argparse
import re
from collections import Counter
import json

#Function to print output based on JSON flag
def print_output(data, json_check):
    if json_check:
        print(json.dumps(data, indent=4))
    else:
        for key, value in data.items():
            print(f"{key}: {value}")
        print()

    #Note: If you loop over a dictionary directly, you only get the keys
    #Note: If you want all items in a dictionary, use .items() method

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('filename', type=str, help='Path to the log file to be analyzed')
    parser.add_argument('--filter', type=str, help='Filter log entries by level (INFO, WARNING, ERROR)', choices=['INFO', 'WARNING', 'ERROR'], default=None)
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')

    args = parser.parse_args()

    #Assign arguments to variables
    filename = args.filename
    filter_level = args.filter
    json_status = args.json

    #Initialize counters for each log level
    count_info = 0
    count_warning = 0   
    count_error = 0
    count_malformed = 0

    #Define a regex pattern to match log lines
    pattern = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>[A-Z]+)\] (?P<message>.+)$', re.IGNORECASE)

    #Initialize a list to store error messages
    errors = []

    with open(filename, 'r') as reader:
        log_data = reader.readlines()
        
        #Check if log_data is empty, if it is, raise an error
        if all(line.strip() == "" for line in log_data) :
            raise ValueError("Log file is empty or could not be read.")
        
        for line in log_data:
            if line.strip() == "":
                continue #Skip the rest of the loop for empty lines
            
            #Use the regex pattern to match string line
            m = pattern.match(line)

            #If no match, increment malformed counter and continue to next line
            if m is None:
                count_malformed +=1
                continue #Skip the rest of the loop for malformed lines

            #Extract components from the matched line
            timestamp = m.group("timestamp")
            level = m.group("level")
            message = m.group("message")    

            #Check Log Levels
            if level == "INFO": 
                count_info +=1
            elif level == "WARNING":
                count_warning +=1
            elif level == "ERROR":
                count_error +=1
                    
                #With the extracted message, we can add it to the errors list
                #Note: To add values to a list, we use the .append() method
                errors.append(message)

    #Now, we use the Counter class from the collections module
    #Counter is a DICTONARY that counts occurrences of each element in a list (or string)
    #and outputs (element: count)
    counts = Counter(errors)

    #Create output dictionary (for JSON output)
    output = {"INFO": count_info,
            "WARNING": count_warning,
            "ERROR": count_error,
            "MALFORMED": count_malformed,
            "Top Errors": counts.most_common(3)}
            #Above, we access 2 variables in the counts dictionary: err and count
            #The .most_common() method returns key-value pairs from a dictionary in groups of tuples
            #(3) indicates we want the top 3 most common error messages
            #Then, we can take the tuples and assign them to two variables (err and count)

    #Print output based on filter level 
    if filter_level == "INFO":
        print_output({"INFO": count_info}, json_status)
    elif filter_level == "WARNING":
        print_output({"WARNING": count_warning}, json_status)
    elif filter_level == "ERROR":
        print_output({"ERROR": count_error}, json_status)
    else:
        print_output(output, json_status)   

if __name__ == "__main__":
    main()