# What's this?
Parsing windows events for sumologic's collector can be a challenge, one common solution is to use regexes but those are not performant and cause both lag for the customer and increase the cost for us.

However the data has a huge advantage in that it follows the same pattern depending on the windows event ID. The terraform configuration contains a set of FER that parse different windows events with the values expected by CSE.

# How to use it?
1. Generate, if you don't have one, an access id/key from sumologic, https://help.sumologic.com/Manage/Security/Access-Keys. Save them somewhere safe
1. Set SUMOLOGIC_ENVIRONMENT to the region for the customer
1. Set SUMOLOGIC_ACCESSID and SUMOLOGIC_ACCESSKEY to the id and key obtained it the step above.
1. Run `terraform apply`, it will ask you whether to create (or update) the rules.

# Known issues
#### FERs are always marked as modified.
I don't know why but the rules are always marked as having changes, but looking at the diff there's nothing changing.

# Migrating from previous rules.
If the customer already had FERs and we want to migrate to this set of rules then I recommend doing the following:
1. Change the prefix for all fields from `EventData` to `EventDataNew`.
1. Create the new rules
1. Verify all the required fields with EventDataNew are correct.
1. Change the prefix for all fields from `EventDataNew` to `EventData`.
1. Update the rules and disabled the existing rules
