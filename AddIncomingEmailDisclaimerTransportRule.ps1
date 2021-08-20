$Disclaimer='<p><div style="background-color:#FFEB9C; width:100%; border-style: solid; border-color:#9C6500; border-width:1pt; padding:2pt; font-size:10pt; line-height:12pt; font-family:Calibri; color:Black; text-align: left;"><span style="color:#9C6500"; font-weight:bold;>External Eamil Warning:</span> This email originated outside of the organization. Please use caution with links or attachments.</div><br></p>'

New-TransportRule "External Email Warning" -FromScope NotInOrganization -SentToScope InOrganization -PrependSubject [EXTERNAL]: -Priority 0 -ApplyHtmlDisclaimerText $Disclaimer -ApplyHtmlDisclaimerLocation Prepend -ApplyHtmlDisclaimerFallbackAction Wrap

