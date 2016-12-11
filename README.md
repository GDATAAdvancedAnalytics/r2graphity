# r2graphity

Usage
=====

graphity.py [-h] [-a] [-p] [-i] [-l] [-b] [-n] input


positional arguments:

  input           Tool requires an input file, batch processing not yet implemented


optional arguments:

  -h, --help      show this help message and exit
  
  -a, --all       Perform all analysis options - graph creation, printing the graph, printing the graph info, plotting, behavior scanning and Neo4j parsing
  
  -p, --printing  Print the graph as text, as in, nodes with respective content
  
  -i, --info      Print info and stats of the graph
  
  -l, --plotting  Plotting the graph via pyplot
  
  -b, --behavior  Scan for behaviors listed in graphityFunc.py
  
  -n, --neodump   Dump graph to Neo4j (configured to flush previous data from Neo, might wanna change that)
  


R2Graphity is built to construct a graph structure based on the function call graph of a Windows executable. Details on how the graph is built and processing options can be found in the attached slide deck, presented at H2HC 2016 in Sao Paulo, Brasil. 


Dependencies
============

radare2		https://github.com/radare/radare2

r2pipe		https://github.com/radare/radare2/wiki/R2PipeAPI

NetworkX		https://github.com/networkx/

Neo4j			https://neo4j.com/download/

py2neo		http://py2neo.org/v3/

numpy			https://github.com/numpy/numpy

pefile		https://github.com/erocarrera/pefile

pydeep		https://github.com/kbandla/pydeep


Watch out to install radare2 from the git repository, do not use the Debian package. 
