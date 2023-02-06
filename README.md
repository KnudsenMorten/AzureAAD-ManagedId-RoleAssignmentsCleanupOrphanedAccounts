This script covers 2 topics : 

(1) how you can automate clean-up of any orphaned security principal role assignments - shown as 'identity not found' role assignments.

(2) how you can implement a daily quality-assurance process for Azure Policy Managed Identity Role Assignment to enforce Azure Policy remediation is always working. 

I use the script as part of implementing a desired-state / quality-assurance process, to keep Azure "clean" without leftovers - and to ensure Azure Policy compliance enforcement is working as expected. It is important to run this with a defined frequency, as Azure Policy might stop to work, if role assignments are deleted or policy definition is changed after initial deployment.

This scripts also shows how you can extract most information from Azure Resource Graph.
