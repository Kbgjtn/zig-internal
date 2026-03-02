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

### Character Encoding
Before a parser can interpret structure of XML Document, it must understand
the characters. Character encoding is the process of assigning a unique 
numerical value (code point) to each character in a given set. This refers
to the method used to represent characters as a sequence of bytes for 
transmission or storage.

While schemes like ISO-8859-1 and ASCII exists, UTF-8 (8-bit format) has 
become the dominant standard for XML parsers.

#### UTF-8
Developed in the 1990s, UTF-8 is backward compatible with ASCII. This means 
any text written in ASCII is automatically valid UTF-8. However, unlike 
ASCII, UTF-8 can represent over 143,000 characters.

UTF-8 is a variable-length encoding scheme. It uses one to four bytes to 
represent each character in the Unicode character set. This design allows
it to represent virtualyy every character from every writing system, from 
ascii to complex multi-bytes scripts and emojis.
