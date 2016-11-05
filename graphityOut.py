#!/usr/bin/env python

import sys 	
import os 
import py2neo
import networkx as nx
import numpy as np
from graphityUtils import gimmeDatApiName, getAllAttributes


# TODO update this parser
def toNeo(graphity, mySha1, myFileSize, myBinType):

	# GRAPH DB STUFF - NEO4J
	# receives the NetworkX graph and accompanying sample data
	# pushes the graph to Neo4J
	
	py2neo.authenticate("localhost:7474", "<USERNAME>", "<PASS>")
	neoGraph = py2neo.Graph("http://localhost:7474/")
	
	# flush of the DB, DEACTIVATE for mass storing of samples
	neoGraph.delete_all()
	
	# create node for binary information
	sampleNode = py2neo.Node("SAMPLE", sha1=mySha1, fileSize=myFileSize, binType=myBinType)
	neoGraph.create(sampleNode)

	# parsing of the NetworkX graph - functions, APIs and strings are all Neo4j nodes
	for nxNode in graphity.nodes(data=True):
	
		funcAddress = nxNode[0]
		funcCalltype = nxNode[1]['calltype']
		funcSize = nxNode[1]['size']
	
		functionNode = py2neo.Node("FUNCTION", mySha1, address=funcAddress, callType=funcCalltype, funcSize=funcSize)
		neoGraph.create(functionNode)
	
		stringList = nxNode[1]['strings']
		
		for stringData in stringList:
			strRefAddress = stringData[0]
			theString = stringData[1]
		
			# TODO think about string attributes to store, e.g. entropy, len
			try:
			
				# create string node or merge if string already exists, add relationship
				stringNode = py2neo.Node("STRING", string=theString)
				# TODO try this using Subgraph class, less interaction with DB server
				neoGraph.merge(stringNode)
		
				stringRel = py2neo.Relationship(functionNode, "references_string", stringNode, address=strRefAddress)
				neoGraph.create(stringRel)
				
			except:
				print "ERROR with this string %s" % theString
			
		callsList = nxNode[1]['calls']
		
		for callData in callsList:
			callRefAddress = callData[0]
			callApiName = callData[1]
		
			# create API node or merge if API already exists, add relationship
			apiNode = py2neo.Node("API", apiname=callApiName)
			neoGraph.merge(apiNode)
		
			apiRel = py2neo.Relationship(functionNode, "calls_api", apiNode, address=callRefAddress)
			neoGraph.create(apiRel)
	
	for from_node, to_node, properties in graphity.edges(data=True):
		# TODO regarding find_one: This method is intended to be used with a unique constraint and does not fail if more than one matching node is found
		# TODO look into NodeSelector instead of find_one
		
		realFromNode = neoGraph.find_one("FUNCTION", property_key="address", property_value=from_node)
		realToNode = neoGraph.find_one("FUNCTION", property_key="address", property_value=to_node)
		
		funcCallsFunc =  py2neo.Relationship(realFromNode, "calls_sub", realToNode)
		neoGraph.create(funcCallsFunc)

	
# fetching NetworkX graph from Neo, still to do
def fromNeo():
	pass
	

# print functions, their APIs and strings to the commandline, enhancements needed
def printGraph(graphity):

	# TODO add more info to print, alias and stuff, sample info
	# print dangling APIs
	# print dangling strings
	
	for item in graphity.nodes(data=True):
		print item[0]
		if 'alias' in item[1]:
			print "Node alias: " + item[1]['alias']
	
		# mix up API calls and strings and sort by offset
		callStringMerge = item[1]['calls'] + item[1]['strings']
		callStringMerge.sort(key=lambda x: x[0])
	
		for cx in callStringMerge:
			print cx


# Printing all the meta info to cmdline
def printGraphInfo(graphity, debug):
	
	# GENERAL INFO
	print ".\nGeneral graph info:"
	allAtts = getAllAttributes(sys.argv[1])
	print "SAMPLE " + allAtts['filename']
	print "Type: " + allAtts['filetype'] 
	print "Size: " + str(allAtts['filesize'])
	print "MD5: " + allAtts['md5']
	print nx.info(graphity)
	
	# GRAPH PARSING INFO
	print ".\nGraph measurement data:"
	print "%6d Total functions detected with 'aflj'" % debug['functions']
	print "%6d Count of references to local functions" % debug['refsFunctions']
	print "%6d Count of references to data section, global variables" % debug['refsGlobalVar']
	print "%6d Count of references to unrecognized locations" % debug['refsUnrecognized']
	print "%6d Total API refs found via symbol xref check" % debug['apiTotal']
	print "%6d Count APIs w/o function xref" % debug['apiMisses']
	print "%6d Total referenced Strings" % debug['stringsReferencedTotal']
	print "%6d Count of dangling strings (w/o function reference)" % debug['stringsDanglingTotal']
	print "%6d Count of strings w/o any reference" % debug['stringsNoRefTotal']
	
	# TODO resources list
	
	
	try:
		degrees = nx.out_degree_centrality(graphity)
	except:
		degrees = 0
	
	indegrees = graphity.in_degree()
	
	# SPAGHETTI CODE METRICS
	print ".\nFat node detection with out-degree centrality, count calls, count strings:"
	if degrees:
		sortit = sorted(degrees, key=degrees.get, reverse=True)	
		for val in sortit[:20]:
			print "%s %.6f %d %d" % (val, degrees[val], len(graphity.node[val]['calls']), len(graphity.node[val]['strings']))

	print '.'
	
	# OUT DEGREE CENTRALITY HISTOGRAM
	print "Histogram of out degree centrality:"
	nummy = np.array(degrees.values())
	bins = [0, 0.0005, 0.001, 0.0015, 0.002, 0.004, 0.006, 0.008, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5]	
	hist, bin_edges = np.histogram(nummy, bins=bins)
	for be in bin_edges:
		print be,
	print ""
	for hi in hist:
		print hi,
	print "\n."
	
	# LOOSE NODE COUNT
	numInZero = 0
	for val in indegrees:
		if indegrees[val] == 0:
			numInZero = numInZero + 1
	nodeNum = graphity.number_of_nodes()
	if not nodeNum:
		nodeNum = 1
	
	print "Loose nodes %d of total %d, thats %f%%" % (numInZero, nodeNum, 100.0 * (float(numInZero) / float(nodeNum)))	
	
	# RATIO OF API CALLS AND STRINGS WITHING CODE SECTION
	print ".\nExecSize FunctionCount ApiCount StringCount"
	print "%d %d %d %d" % (debug['xsectionsize'], debug['functions'], debug['apiTotal'], debug['stringsReferencedTotal']) # code section size, function count, total api, total string
	
	kilobytes = (float(debug['xsectionsize']) / 1000.0)
	if kilobytes > 0:
		print "Per-Kilobyte ratio"
		print float(debug['functions']) / kilobytes, float(debug['apiTotal']) / kilobytes, float(debug['stringsReferencedTotal']) / kilobytes
	
	# AVERAGE DEGREE CONNECTIVITY
	print ".\nAverage degree connectivity per degree k:" #average nearest neighbor degree of nodes with degree k
	avConn = nx.average_degree_connectivity(graphity)
	for connectivity in avConn:
		print "%3d %.6f" % (connectivity, avConn[connectivity])
		
	print "."
	
	# GETPROCADDRESS DETECTION, not a suuuuper useful metric, but interesting to look at, different from beh. detection, cause count is total
	allCalls = nx.get_node_attributes(graphity, 'calls')
	gpaCount = 0
	
	for function in allCalls:
		for call in allCalls[function]:
			if 'GetProcAddress' in call[1]:
				gpaCount = gpaCount + 1
	
	print "Found %d calls to GetProcAddress\n." % gpaCount
	
	# TODO number of nodes w strings/apis vs. nodes w/o
	
	
# Graph plotting with pydotplus from within NetworkX, format is dot 
def plotSeGraph(graphity):

	pydotMe = nx.drawing.nx_pydot.to_pydot(graphity)
	for node in pydotMe.get_nodes():
		
		finalString = ''
		if node.get('calls') != '[]' or node.get('strings') != '[]':

			# TODO THE single ugliest piece of code I ever wrote. Now I'll promise to fix this in the future, priority -1... duh
			finalList = []
			for item in node.get('calls').split('[\''):
				if item.startswith('0x'):
					stuff = item.split('\'')
					finalList.append(str(stuff[0]) + ": [C] " + str(stuff[2]))
			try:
				for otherItem in node.get('strings').split('[\''):
					if otherItem.startswith('0x'):
						stuff = otherItem.split('\'')
						finalList.append(str(stuff[0]) + ": [S] " + str(stuff[2]))
			except:
				print "Trouble with string " + str(stuff)
							
			finalList.sort()
			finalString = '\n'.join(finalList)
			
		if node.get('type') == 'Export':
			label = "Export " + node.get('alias')
			label = label + "\n" + finalString
			node.set_fillcolor('skyblue') 
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)
		
		elif node.get('type') == 'Callback':
			label = "Callback " + "\n" + finalString
			node.set_fillcolor('darkolivegreen1') 
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(label)
		
		elif finalString != '':
			# TODO add address of node as title
			# finalString = str(node) + '\n' + finalString
			node.set_fillcolor('lightpink1')
			node.set_style('filled,setlinewidth(3.0)')
			node.set_label(finalString)

	# TODO add info about sample to graph
	graphname = os.path.basename(sys.argv[1]) + ".png"
	try:
		# TODO pydotplus throws an error sometimes (Error: /tmp/tmp6XgKth: syntax error in line 92 near '[') look into pdp code to see why
		pydotMe.write_png(os.path.join(os.path.abspath(os.path.dirname(__file__)), graphname))
	except Exception as e:
		print "ERROR drawing graph"
		print str(e)
	
