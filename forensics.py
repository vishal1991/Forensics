#!/usr/bin/python
import optparse
import whois
import socket
import subprocess
import urllib
import pygeoip
import simplekml
import os
import sys
from sqlalchemy import *

def main():

#---------------------------------Provide options to user, utlizing optparse library-----------------------------------

	parser = optparse.OptionParser('\nUsage: forensics.py '+'-u <URL list> -g <Location of GeoCityLite database> -r <Text report> -d <SQLite report> -k <KML file> -f <Log failed URL>\n')
	parser.add_option('-u', dest='urlfile', help='specify URL file')
	parser.add_option('-g', dest='geo', help='Location of GeoCityLite database')
	parser.add_option('-r', dest='reportfile', help='Specify report file')
	parser.add_option('-d', dest='dbfile', help='Specify database file')
	parser.add_option('-k', dest='kmlfile', help='Specify kml file')
	parser.add_option('-f', dest='fail_log', help='Log failed URL')

	(options, args) = parser.parse_args()
	url_file = options.urlfile
	geo_file = options.geo
	report_file=options.reportfile
	db_file = options.dbfile
	kml_file = options.kmlfile
	log = options.fail_log

	if url_file == None or geo_file == None or not os.path.isfile(url_file)  or not os.path.isfile(geo_file) :
		print parser.usage
		exit(0)

	if report_file != None:
		if os.path.isfile(report_file):
			print 'Output Filename already exists\nPlease provide unique Filename'
			exit(0)
	if kml_file != None:
		if os.path.isfile(kml_file):
			print 'Output Filename already exists\nPlease provide unique Filename'
			exit(0)
	if db_file != None:
		if os.path.isfile(db_file):
			print 'Output Filename already exists\nPlease provide unique Filename'
			exit(0)
	if log != None:
		if os.path.isfile(log):
			print 'Output Filename already exists\nPlease provide unique Filename'
			exit(0)
	if log != None:
		logfile = open(log,'wb')

	fp = {}
	fd = open(url_file, 'r')
	gi = pygeoip.GeoIP(geo_file)
	city = ''
	country = ''
	region = ''
	lat = ''
	longt = ''
	report = False
	database = False
	kl = False
	socket.setdefaulttimeout(2)

#---------------------------------------Create text based report file ----------------------------------------------
	
	if report_file != None:
		report = True
		fdes  = open(report_file,'wb')

#--------------------------------------Create SQLite database using sqlalchemy---------------------------------------
	
	if db_file != None:
		
		database = True
		db = create_engine('sqlite:///'+str(db_file))
		db.echo = False
		metadata = MetaData(db)
		data = Table ('IP_Geolocation', metadata,
			Column('URL',String(200),primary_key=True),
			Column('Whois', String(5000)),
			Column ('IPv4', String(110)),
			Column('Fingerprinting', String(1000)),
			Column('City', String(100)),
			Column('Country',String(100)),
			Column('Longitude',Integer),
			Column('Latitude',Integer)
			)
		data.create()
		i = data.insert()

#---------------------------------------------Setup KML file -----------------------------------------------------------	
	if kml_file != None:
		kmlf = open(kml_file,'wb')
		kml = simplekml.Kml()
		kl = True

#----------------------------------------------Looping through each URL in list -------------------------------------------
	for url in fd:

#----------------------------------------------Analyse each URL-----------------------------------------------------		
		try:
	
			domain = whois.whois(url)
			d = domain.domain_name[0]
			ip_addr = socket.gethostbyname(d)
			http_response = urllib.urlopen(url)
			headers = http_response.headers 
			rec = gi.record_by_name(ip_addr)
			city = rec['city']
			country = rec['country_name']
			longt = rec['longitude']
			lat = rec['latitude']

# --------------------------------------------Feed Information to a text based report--------------------------------------
			
			if report:
				fdes.write('\n\n'+str(url)+'\n')
				fdes.write('----------------------------------------------------------------------------\n')				
				fdes.write('-----------------------------Whois Information-------------------------------\n')
				fdes.write(str(domain)+'\n')								
				#fdes.write('Whois Information\n'+str(domain)+'\n')
				fdes.write('-----------------------------IPv4 Address------------------------------------\n')				
				fdes.write('IPv4 Address: '+str(ip_addr)+'\n')
				fdes.write('-----------------------------Response Headers--------------------------------\n')				
				fdes.write(str(http_response.code)+'\n')
				fdes.write(str(http_response.headers)+'\n')
				#fdes.write(str(http_response.headers['Server'])+'\n')
				fdes.write('-----------------------------Geolocation Information-------------------------\n')
				fdes.write('City: '+str(city)+'\n')
				fdes.write('Country: '+str(country)+'\n')
				fdes.write('Longitude: '+str(longt)+'\n')
				fdes.write('Latitude: '+str(lat)+'\n')

#------------------------------------------------ Feed information into SQLite database-------------------------------------

			if database: 
				i.execute(URL=unicode(url), Whois=unicode(domain), IPv4=unicode(ip_addr), Fingerprinting=unicode(headers), City=unicode(city), Country= unicode(country), Longitude=unicode(longt), Latitude=unicode(lat))


#-----------------------------------------------Feed information into KML file--------------------------------------		
			if kl:
				kml.newpoint(name=city or ip_addr, coords=[(lat,longt)])
				kml.save(kml_file)

		except Exception, e:
			try:
				logfile.write(str(url)+'\n')
			except Exception, e:
				pass
			


main()

		
		
	







