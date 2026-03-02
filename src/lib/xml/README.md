[Extensible Markup Language (XML) 1.0 (Fifth Edition)](https://www.w3.org/TR/REC-xml/)

### Syntax Rules:
An XML document must:
- Have exactly single Root Element
- Proper Nesting Elements
- Properly closed tags
- Case-sensitivity
- Use Quoted Attribute values
- Use valid Character Encoding (UTF-8/UTF-16 required support)
- Schema Definition, xml documents can define their own custom 
  tags and attributes using a Document Type Definition (DTD) or 
  an XML Schema.

### XML Parsers

There are some commonly used methods are:
#### DOM Parser
A DOM (Document Object Model) parser reads the complete XML document and
builids a tree structure in memory. While it offers advantages in random
access and full manipulation of the document, it consumes large amounts 
of memory, especially with extensive XML files. It is best suited for 
smaller documents or when requent modification to the document structure
are required.

#### SAX Parser
In contrast, SAX (Simple API for XML) is a streaming parser that reads XML
files sequentially, and generates "events" (notification) as it encounters
different parts of the document like a token, then processing each element 
as it is read without loading the entire file into memory. This method is 
ideal for processing large XML documents or applications with limited memory. 
However, since it does not store the entire document structure, SAX is more
appropriate when only certain elements or sequential processing is needed.

#### StAX Parser
For those looking for a balance and control, the StAX (Streaming API for XML)
parser is often the answer. StAX combines the benefits of both SAX and DOM. 
Like SAX, it offers event-based processing, which keeps memory usage low. 
However, unlike SAX, it allows the developer to "pull" information from the 
stream rather having events "pushed" to them.


### Choosing the Right Parser
- Use DOM if you have smaller files and need to edit or navigate the structure extensively.
- Use SAX if you are reading massive files and only need to extract specific data once.
- Use StAX if you need high performance and control over when to stop processing the stream.

References:
- https://ithy.com/article/xml-parsing-tips-29mppwre
- https://www.hurix.com/blogs/understanding-the-importance-of-parsers-in-xml/#thestax6
