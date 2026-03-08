![Log Types](https://img.shields.io/badge/Logs-Apache%20%7C%20Custom-lightgrey)
![AWK](https://img.shields.io/badge/Tool-AWK-yellow)  
![sed](https://img.shields.io/badge/Tool-sed-orange)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue?logo=linux)
![Bash](https://img.shields.io/badge/Scripting-Bash-green?logo=gnu-bash) 


# Log Data Normalization Utility Overview.
This project provides a series of Linux-based processing scripts designed to perform **Data Normalization** on disparate security log sources. In a Security Operations Center (SOC) environment, log sources often utilize inconsistent timestamp formats (e.g., Unix Epoch vs. ISO 8601) and varying delimiters. This utility standardizes these logs into a universal, human-readable format to facilitate high-fidelity event correlation and SIEM ingestion.

## Technical Specifications.
- **Environment:** Linux / Security onion   
- **Core Tools:** AWK, Bash, sed
- **Log Types Handled:** Apache Web Logs, Custom Application Logs (Pipe-delimited).

## Key Functionalities.
- **Timestamp Conversion:** Automated conversion of Unix Epoch strings to Human-Readable (UTC) format using internal AWK `strftime` functions.
- **Schema Standardization:** Parsing of non-standard delimiters (`|`) to ensure consistent field mapping.
- **Data Sanitization:** Removal of EOF (End of File) artifacts and whitespace inconsistencies that frequently cause ingestion failures in log parsers.
- **Security Onion Integration:** Prepared datasets for ingestion into the Elastic Stack (ELK) for centralized monitoring.

## Usage.
To normalize a raw application log with Epoch timestamps in the 3rd column:
```bash
awk 'BEGIN {FS="|"; OFS="|"} {$3=strftime("%c",$3)} {print}' raw_log_file.log > normalized_log.log
```


## Operational Impact.
By implementing these normalization techniques, the time-to-analysis for security incidents is significantly reduced. Analysts can perform accurate cross-platform timeline analysis without manual time-conversion—ensuring that events from web servers and internal applications are perfectly synchronized during an investigation.
