#!/bin/bash 

######################################################################
#Script Name	: weather                                                                                             
#Description	: Display weather forcast for nearest airport in term                                                                                
#Args           : 3 Letter IATA code                                                                                          
#Author       	:Richard Goddard                                                
#Email         	:richard.goddard@itcdefense.com                                           
######################################################################

echo "Enter nearest airport three letter IATA code and press [ENTER]:"
read IATA

curl wttr.in/"{"$IATA"}"
