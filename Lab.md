___
# Trigger A

## Implementation Details

### Workflow Architecture

![[Pasted image 20251225232918.png]]

The n8n workflow consists of 14 interconnected nodes organized into a logical pipeline:

**Phase 1: Initialization and Data Extraction**

- Manual Trigger node to start the workflow on demand
- Pagination initialization to prepare for large-scale data retrieval
- API connection to Kibana detection engine

**Phase 2: Rule Processing**

- Iterative pagination handling to retrieve all rules
- Data parsing and field extraction
- Conditional routing based on MITRE mapping status

**Phase 3: AI Enhancement and Storage**

- AI-powered MITRE mapping for unmapped rules
- Data transformation and standardization
- Google Sheets storage for final inventory

---

### Step-by-Step Implementation

#### Step 1: Workflow Initialization

##### ##### Node: "Start Trigger A"**

- Type: Manual Trigger
- Purpose: Provides on-demand execution control for the workflow

##### ##### Node: "Initialize Pagination"**

- Type: Code (JavaScript)
- Purpose: Sets up initial parameters for paginated API calls

```javascript
return {
  json: {
    kibana_url: 'http://208.73.204.77:5601',
    page: 1,
    per_page: 100,
    all_rules: [],
    continue_loop: true
  }
};
```

This initialization establishes:

- SIEM endpoint URL
- Starting page number
- Rules per page limit (100)
- Empty array to accumulate all rules
- Loop continuation flag

#### Step 2: Paginated Rule Extraction

##### ##### Node: "Fetch Rules Page {{$json.page}}"**
  ![[Pasted image 20251226091507.png]]
- Type: HTTP Request
- Method: GET
- Authentication: HTTP Basic Auth
- Endpoint: `/api/detection_engine/rules/_find?per_page=100&page={{$json.page}}&filter=alert.attributes.enabled:true`

Key configuration:

- Custom headers: `kbn-xsrf: true` (required by Kibana API)
- Filter parameter: `alert.attributes.enabled:true` (only enabled rules)
- Dynamic page number from previous node

##### ##### Node: "Log Progress"**

- Type: Code (JavaScript)
- Purpose: Provides visibility into extraction progress

```javascript
const response = $input.first().json;
const page = response.page || 1;
const total = response.total || 0;
const dataLength = (response.data || []).length;

console.log(`📄 Fetched page ${page} - Got ${dataLength} rules out of ${total} total`);

return $input.all();
```

#### Step 3: Pagination Control

##### Node: "Process Page & Check Continue"**

- Type: Code (JavaScript)
- Purpose: Manages pagination state and determines when to stop

```javascript
const currentState = $('Initialize Pagination').first().json;
const apiResponse = $input.first().json;

const rulesInPage = apiResponse.data || [];
const total = apiResponse.total || 0;
const currentPage = apiResponse.page || currentState.page;
const perPage = apiResponse.per_page || currentState.per_page;

const totalPages = Math.ceil(total / perPage);
const hasMorePages = currentPage < totalPages;

const allRules = [...currentState.all_rules, ...rulesInPage];

return {
  json: {
    kibana_url: currentState.kibana_url,
    page: currentPage + 1,
    per_page: perPage,
    all_rules: allRules,
    continue_loop: hasMorePages,
    current_page: currentPage,
    total_pages: totalPages,
    total_rules: total,
    rules_fetched: allRules.length
  }
};
```

##### Node: "Has More Pages?"**
  ![[Pasted image 20251226091604.png]]
- Type: IF Condition
- Logic: Compares current page against total pages
- True branch: Loops back to fetch next page
- False branch: Proceeds to rule processing

This creates a loop that continues until all pages are retrieved.

#### Step 4: Rule Data Splitting

![[Pasted image 20251226091632.png]]

##### Node: "Split rules"**

- Type: Split Out
- Field: `all_rules`
- Purpose: Converts array of rules into individual items for processing

##### Node: "extract specific Fields"**

- Type: Set (Edit Fields)
- Purpose: Extracts essential fields from each rule for downstream processing

Fields extracted:

- `id`: Internal rule identifier
- `rule_id`: External rule identifier
- `name`: Rule name
- `description`: Rule description
- `threat`: MITRE ATT&CK mappings (array)
- `required_fields`: Fields needed for rule to execute
- `index`: Target log sources/indexes
- `type`: Rule type (query, eql, threshold, etc.)
- `framework`: Threat framework (MITRE ATT&CK)
- `query`: Detection query logic

#### Step 5: MITRE Mapping Decision

![[Pasted image 20251226091705.png]]

##### Node: "Check if Rule Needs MITRE Mapping"**

- Type: IF Condition
- Condition: `{{ $json.threat }}` is empty
- Purpose: Routes rules based on existing MITRE mappings

Logic:

- If `threat` array is empty → Route to AI mapping
- If `threat` array has data → Route to direct processing

This optimization prevents unnecessary AI API calls for rules that already have MITRE mappings.

#### Step 6: AI-Powered MITRE Mapping

![[Pasted image 20251226091732.png]]

##### Node: "Message a model"**

- Type: Google Gemini AI
- Model: `models/gemma-3-1b-it`
- Purpose: Analyzes rule and returns MITRE ATT&CK mapping

**AI Prompt Structure:**

```
## System Context
You are a cybersecurity expert specializing in SIEM detection engineering and MITRE ATT&CK framework mapping. You work for a SOC team that needs to automatically map detection rules to MITRE techniques.

## Task Description
Analyze the given SIEM detection rule and identify which MITRE ATT&CK technique(s) it detects. Consider the rule logic, query patterns, and context.

## Output Requirements
Return ONLY a JSON object with this exact structure:
{
    "rule_id": "ded09d02-0137-4ccc-8005-c45e617e8d4c",
    "rule_name": "Query Registry using Built-in Tools",
    "rule_description": "This rule identifies the execution of commands that can be used to query the Windows Registry. Adversaries may query the registry to gain situational awareness about the host, like installed security software, programs and settings.",
    "rule_type": "new_terms",
    "mitre_framework": "MITRE ATT&CK",
    "mitre_tactic_id": "TA0007",
    "mitre_tactic_name": "Discovery",
    "mitre_techniques": "T1012",
    "mitre_technique_names": "Query Registry",
    "mitre_subtechniques": "",
    "required_fields": "event.category, event.type, host.os.type, process.args, process.command_line, process.name.caseless",
    "required_fields_count": 6,
    "log_sources": "logs-endpoint.events.process-*",
    "log_source_count": 1,
    "query_type": "new_terms",
    "has_query": true,
    "coverage_status": "PENDING",
    "last_checked": null,
    "original_rule_id": "dc944235-222b-4fa6-8e7c-4d0652bb6bbe",
    "original_rule_name": "Query Registry using Built-in Tools"
  },


## Critical Rules
1. **ONLY return valid JSON**, no additional text
2. **Use exact MITRE IDs** from official ATT&CK framework
3. **If uncertain**, use parent technique instead of sub-technique
4. **Never** return multiple techniques in one mapping
5. **Always** include all four fields in the JSON

## Ready for Analysis
Now analyze the following rule and provide MITRE mapping:
id:{{ $json.id }}
rule_id:{{ $json.rule_id }}
name:{{ $json.name }}
description:{{ $json.description }}
required_filed:{{ $json.required_fields }}
index :{{ $json.index }}
query: {{ $json.query }}

```

The prompt provides:

- Rule context and metadata
- Query logic for analysis
- Strict JSON output format requirements
- Guidelines for accurate MITRE mapping

##### Node: "Split Out Ai response"**
  ![[Pasted image 20251226091802.png]]
- Type: Split Out
- Field: `content.parts`
- Purpose: Extracts the AI response text from the API response structure

##### Node: "text -> json"**

![[Pasted image 20251226091829.png]]

- Type: Code (JavaScript)
- Purpose: Cleans and parses AI response into JSON

```javascript
const items = $input.all();

for (const item of items) {
  const rawText = item.json.text;
  
  const cleanedText = rawText
    .replace(/```json/g, '')
    .replace(/```/g, '')
    .trim();
  
  item.json = JSON.parse(cleanedText);
}

return items;
```

This handles:

- Removal of markdown code blocks
- Trimming whitespace
- JSON parsing with error handling

#### Step 7: Rule Requirements Extraction

##### Node: "Extract Rule Requirements"**

![[Pasted image 20251226092021.png]]

- Type: Code (JavaScript)
- Purpose: Parses and structures rule metadata for rules with existing MITRE mappings

Key processing logic:

```javascript
// Extract MITRE technique(s) - handle multiple techniques
let mitreTechniques = [];
if (ruleData.threat && Array.isArray(ruleData.threat)) {
  for (const threat of ruleData.threat) {
    if (threat.technique && Array.isArray(threat.technique)) {
      for (const tech of threat.technique) {
        const technique = {
          id: tech.id || '',
          name: tech.name || '',
          subtechnique: tech.subtechnique && Array.isArray(tech.subtechnique) 
            ? tech.subtechnique.map(st => ({ id: st.id, name: st.name }))
            : []
        };
        mitreTechniques.push(technique);
      }
    }
  }
}

// Parse required_fields from JSON string
let requiredFields = [];
try {
  if (ruleData.required_fields && ruleData.required_fields !== '[]') {
    const fieldsJson = JSON.parse(ruleData.required_fields);
    if (Array.isArray(fieldsJson)) {
      requiredFields = fieldsJson.map(field => field.name || 'unknown');
    }
  }
} catch (error) {
  requiredFields = ['ERROR_PARSING_FIELDS'];
}
```

The code handles:

- Nested MITRE technique arrays
- Sub-technique extraction
- JSON string parsing for required fields
- Error handling for malformed data
- Array formatting for log sources

Output structure:

```javascript
{
  rule_id: "...",
  rule_name: "...",
  rule_description: "...",
  rule_type: "...",
  mitre_framework: "MITRE ATT&CK",
  mitre_tactic_id: "...",
  mitre_tactic_name: "...",
  mitre_techniques: "T1012, T1082",
  mitre_technique_names: "Query Registry, System Information Discovery",
  mitre_subtechniques: "T1012.001",
  required_fields: "event.category, host.os.type, process.name",
  required_fields_count: 3,
  log_sources: "logs-endpoint.events.process-*",
  log_source_count: 1,
  query_type: "query",
  has_query: true,
  coverage_status: "PENDING",
  original_rule_id: "..."
}
```

#### Step 8: Data Storage

![[Pasted image 20251226092053.png]]

##### Node: "Store Rules in Google Sheet"** (for rules with existing MITRE mappings) ##### Node: "Store Rules in Google Sheet1"** (for AI-mapped rules)

- Type: Google Sheets
- Operation: Append
- Document ID: `1VQQuZZRuMVy4yWgNLMdcDXDQuDzJLgjN-GEmYQHxrjM`
- Sheet: "الورقة1"

Column mappings:

```
Rule ID → rule_id
Rule Name → rule_description
Description → rule_description
Rule Type → rule_type
MITRE Framework → mitre_framework
MITRE Tactic ID → mitre_tactic_id
MITRE Tactic Name → mitre_tactic_name
MITRE Technique IDs → mitre_techniques
MITRE Technique Names → mitre_technique_names
MITRE Subtechniques → mitre_subtechniques
Required Fields → required_fields
Required Fields Count → required_fields_count
Log Sources → log_sources
Log Source Count → log_source_count
Query Available → has_query
Coverage Status → coverage_status
Last Checked → last_checked
Original Rule ID → original_rule_id
```

![[Pasted image 20251226092231.png]]

___
# Trigger B

![[Pasted image 20251226152112.png]]
# Trigger B Implementation Report: Telemetry Inventory and Coverage 


Trigger B is the second phase of the automated detection coverage system. Its primary responsibility is to build a comprehensive telemetry inventory from the SIEM and validate which detection rules can actually function based on available log sources and fields.

## Workflow Architecture

The Trigger B workflow consists of 8 interconnected nodes that work sequentially to gather, process, and validate telemetry data against detection rules.

### Node 1: Start Trigger B (Schedule Trigger)

This node initiates the entire Trigger B workflow on a scheduled basis. It runs at regular intervals to ensure the coverage status remains up-to-date as the SIEM environment changes.

**Configuration:**

- Type: Schedule Trigger
- Webhook ID: trigger-b
- Execution: Interval-based

### Node 2: Get Available Telemetry Fields (HTTP Request)

![[Pasted image 20251226152339.png]]

This node connects to the Kibana API to retrieve all available data views (index patterns) from the SIEM.

**Configuration:**

- URL: `http://208.73.204.77:5601/api/data_views`
- Authentication: HTTP Basic Auth
- Headers: Content-Type application/json
- Method: GET

**Purpose:** Fetches the complete list of data views that represent the log sources configured in the SIEM.

### Node 3: Split Out

![[Pasted image 20251226152357.png]]

This node takes the array of data views returned from Kibana and splits them into individual items for processing.

**Configuration:**

- Field to split: data_view
- Purpose: Enables processing each data view separately in subsequent nodes

### Node 4: Edit Fields

![[Pasted image 20251226152413.png]]

This node extracts and standardizes the key attributes from each data view.

**Extracted Fields:**

- id: Data view identifier
- title: Index pattern or data source name
- name: Human-readable name
- timeFieldName: Timestamp field used for time-based queries

**Purpose:** Normalizes the data structure for consistent processing downstream.

### Node 5: Filter

![[Pasted image 20251226152434.png]]

This node applies a validation check to ensure only valid data views proceed through the workflow.

**Filter Condition:**

- Checks if the "name" field exists
- Case sensitive validation
- Strict type checking enabled

**Purpose:** Removes any malformed or incomplete data view entries.

### Node 6: Get_data_view (HTTP Request)

![[Pasted image 20251226152502.png]]

This node performs a detailed retrieval of each individual data view to access its complete field mapping.

**Configuration:**

- URL: `http://208.73.204.77:5601/api/data_views/data_view/{{ $json.id }}`
- Authentication: HTTP Basic Auth
- Headers: kbn-xsrf: true
- Dynamic URL construction using data view ID

**Purpose:** Fetches the complete field schema for each data source, including all available fields and their properties.

### Node 7: Get-rule-sheet (Google Sheets)

![[Pasted image 20251226152521.png]]

This node retrieves the detection rules from Google Sheets that were populated by Trigger A.

**Configuration:**

- Document ID: 1VQQuZZRuMVy4yWgNLMdcDXDQuDzJLgjN-GEmYQHxrjM
- Sheet Name: الورقة1 (Sheet 1)
- Operation: Read all rows

**Retrieved Data:**

- Rule ID
- Rule Name
- Required Fields
- Log Sources
- MITRE ATT&CK mappings
- All other rule metadata

### Node 8: Code in JavaScript (Coverage Analysis Engine)

![[Pasted image 20251226152604.png]]

This is the core processing node that performs the intelligent matching between available telemetry and rule requirements.

#### Key Functions:

**1. Build Telemetry Source Map**

```javascript
- Collects all available log sources from data views
- Extracts source titles and index patterns
- Builds a normalized set of available sources
```

**2. Build Field Inventory**

```javascript
- Flattens nested field structures from Kibana
- Creates comprehensive field catalog
- Adds ECS field variations (lowercase, .keyword, .text)
- Handles complex object field paths
```

**3. Mapping Layer**

```javascript
- Maps generic source patterns to specific implementations
- Handles common source naming conventions:
  * logs-* → logs-endpoint.events.process-*
  * winlogbeat-* → logs-windows.*
  * endgame-* → logs-endpoint.events.security-*
  * auditbeat-* → logs-system.*
  * filebeat-* → logs-*
```

**4. Source Matcher Function**

```javascript
- Implements wildcard matching for source patterns
- Handles prefix-based matching (e.g., logs-*)
- Performs exact matching for specific sources
```

**5. ECS-Aware Field Matcher Function**

```javascript
- Performs case-insensitive field matching
- Handles ECS field variations (.keyword, .text)
- Implements field equivalence mapping:
  * process.name.caseless ↔ process.name
  * event.type ↔ event.action
  * event.category ↔ event.kind
  * host.os.type ↔ host.os.name
- Handles flattened field name mismatches
```

**6. Rule Coverage Evaluation Logic** For each detection rule, the code:

a) **Parses Rule Requirements:**

- Splits comma-separated log sources
- Splits comma-separated required fields
- Trims and filters empty values

b) **Evaluates Source Coverage:**

- Checks if any required source exists in telemetry
- Tracks missing sources
- Sets sourceCovered flag

c) **Evaluates Field Coverage:**

- Checks each required field against field inventory
- Uses ECS-aware matching
- Categorizes fields as present or missing

d) **Determines Coverage Status:**

- **COVERED:** All sources and fields available
- **PARTIALLY COVERED:** Source available but some fields missing
- **NOT COVERED:** Required source not available

e) **Generates Detailed Output:**

```javascript
{
  mode: "DEBUG COVERAGE",
  rule_id: string,
  rule_name: string,
  coverage_status: "COVERED" | "PARTIALLY COVERED" | "NOT COVERED",
  
  // Source Information
  required_sources_count: number,
  required_sources: array,
  telemetry_sources_available: array,
  missing_log_sources: array,
  
  // Field Information
  required_fields_count: number,
  required_fields: array,
  present_fields_count: number,
  present_fields: array,
  missing_fields_count: number,
  missing_fields: array
}
```

```json output
{
    "mode": "DEBUG COVERAGE",
    "rule_id": "aab184d3-72b3-4639-b242-6597c99d8bca",
    "rule_name": "This rule is triggered when a hash indicator from the Threat Intel Filebeat module or integrations has a match against an event that contains file hashes, such as antivirus alerts, process creation, library load, and file operation events.",
    "coverage_status": "COVERED",
    "required_sources_count": 5,
    "required_sources": [
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "logs-*",
      "winlogbeat-*"
    ],
    "telemetry_sources_available": [
      "logs-network_traffic.*",
      ".alerts-security.alerts-default",
      "security_solution-*.vulnerability_latest",
      "logs-cloud_security_posture.vulnerabilities_latest-default",
      "security_solution-*.misconfiguration_latest",
      "logs-*",
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".kibana-event-log-*",
      "logs-endpoint.events.process-*",
      "logs-endpoint.events.security-*",
      "logs-windows.*",
      "logs-system.security*",
      "logs-system.*"
    ],
    "missing_log_sources": [],
    "required_fields_count": 6,
    "required_fields": [
      "event.category",
      "event.type",
      "host.os.type",
      "process.args",
      "process.command_line",
      "process.name.caseless"
    ],
    "present_fields_count": 6,
    "present_fields": [
      "event.category",
      "event.type",
      "host.os.type",
      "process.args",
      "process.command_line",
      "process.name.caseless"
    ],
    "missing_fields_count": 0,
    "missing_fields": []
  },
  {
    "mode": "DEBUG COVERAGE",
    "rule_id": "29531d20-0e80-41d4-9ec6-d6b58e4a475c",
    "rule_name": "This rule uses alert data to determine when multiple alerts in different phases of an attack involving the same host are triggered and where the accumulated risk score is higher than a defined threshold.",
    "coverage_status": "COVERED",
    "required_sources_count": 1,
    "required_sources": [
      "logs-endpoint.events.process-*"
    ],
    "telemetry_sources_available": [
      "logs-network_traffic.*",
      ".alerts-security.alerts-default",
      "security_solution-*.vulnerability_latest",
      "logs-cloud_security_posture.vulnerabilities_latest-default",
      "security_solution-*.misconfiguration_latest",
      "logs-*",
      "apm-*-transaction*",
      "auditbeat-*",
      "endgame-*",
      "filebeat-*",
      "packetbeat-*",
      "traces-apm*",
      "winlogbeat-*",
      "-*elastic-cloud-logs-*",
      ".kibana-event-log-*",
      "logs-endpoint.events.process-*",
      "logs-endpoint.events.security-*",
      "logs-windows.*",
      "logs-system.security*",
      "logs-system.*"
    ],
    "missing_log_sources": [],
    "required_fields_count": 6,
    "required_fields": [
      "event.category",
      "event.type",
      "host.os.type",
      "process.args",
      "process.command_line",
      "process.name.caseless"
    ],
    "present_fields_count": 6,
    "present_fields": [
      "event.category",
      "event.type",
      "host.os.type",
      "process.args",
      "process.command_line",
      "process.name.caseless"
    ],
    "missing_fields_count": 0,
    "missing_fields": []
  }
```
### Node 9: Update row in sheet (Google Sheets)

This final node writes the coverage analysis results back to Google Sheets.
![[Pasted image 20251226152221.png]]
**Configuration:**

- Operation: Update
- Matching Column: Rule ID
- Document: Detection_Rules spreadsheet

**Updated Columns:**

- Coverage Status: COVERED/PARTIALLY COVERED/NOT COVERED
- Missing Log Sources: Array of unavailable sources
- Missing Fields: Array of unavailable fields

**Purpose:** Persists the coverage analysis results for reporting and visibility.

## Data Flow Summary

1. **Trigger initiation** → Scheduled execution begins
2. **API call to Kibana** → Retrieves all data views
3. **Split data views** → Separates into individual items
4. **Field extraction** → Normalizes data view attributes
5. **Validation filter** → Removes invalid entries
6. **Detailed field retrieval** → Gets complete field mappings per data view
7. **Rule retrieval** → Fetches detection rules from Google Sheets
8. **Coverage analysis** → Intelligent matching of requirements vs. availability
9. **Results persistence** → Updates Google Sheets with coverage status
