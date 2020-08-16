rule SuspiciosStringsRule
{
 strings:
  $a0 = "backdoor" nocase
  $a1 = "virus" nocase
 condition:
   any of them
}

rule EstoNoEsCocaPapiRule
{
 strings:
  $my_text_string = "esto no es coca papi"
 condition:
   $my_text_string
}

rule CreditCardRule
{
 strings:
  $a0 = /[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}/
 condition:
  $a0
}

rule AccessTokenRule
{
 strings:
  $a0 = /TOKEN_([0-9]){4}-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii
 condition:
  any of them
}

rule OldTokenRule
{
 strings:
  $a1 = /TOKEN_2016-(0([2-9]){1}|1(0-2){1})-([0-9]){2}_([0-9])+/ nocase wide ascii 
  $a2 = /TOKEN_(201([7-9]){1}|20([2-9]){1}([0-9]){1})-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii 
 condition:
   any of them
}

