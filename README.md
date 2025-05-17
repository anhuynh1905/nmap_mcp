install all the requirements first, IMPORTANT: install docker and mysql too. Create a database name: nmap_scans (crutial)

in this program, deepseek v3 will be used to analyze nmap data from mcp server. Docker will be used to run nmap, why ? Because you can run as root usr and don't worry about anything, especially scanning a network because everyone will know your IP address. 

features in this program:
- I've create many tools for scanning, you have basic scan (means just basic nmap syntax), aggressive scan (the longest even with -T 4), stealth scan,... find out yourself.
- And a function to extract .xml outputs file, forgot to mention all outputs will be .XML.
- You can use LLM to further analyze like I talk above.
- In short, I spend to much time design the UI, that why html is 50% of the project.
- Remember to add username and password for your mysql server also API key for your LLMs.
- start up the mcp server first and then app.py or other way around 
