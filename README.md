# CoAP.NET - A CoAP library for .NET
The Constrained Application Protocol (CoAP) (https://datatracker.ietf.org/doc/draft-ietf-core-coap/)
is a RESTful web transfer protocol for resource-constrained networks and nodes.
CoAP.NET is an implementation in C# providing CoAP-based services to .NET applications. 
Reviews and suggestions would be appreciated.

## Copyright
Copyright (c) 2011-2013, Longxiang He <<longxianghe@gmail.com>>, SmeshLink Technology Co.<br>
Copyright (c) 2016-2020, Jim Schaad <<ietf@augustcellars.com>><br>
Copyright (c) 2023-, Stephen Berard <<stephen.berard@outlook.com>><br>

## How to Install
The C# implementation is available in the NuGet Package Gallery under the name [CoAP.NET](https://www.nuget.org/packages/CoAP.NET).
To install this library as a NuGet package, enter 'Install-Package CoAP.NET' in the NuGet Package Manager Console.

## Documentation
Coming soon

### CoAP Client
Access remote CoAP resources by issuing a **[Request](CoAP.NET/Request.cs)**
and receive its **[Response](CoAP.NET/Request.cs)**(s).

```csharp
  // new a GET request
  Request request = new Request(Method.GET);
  request.URI = new Uri("coap://[::1]/hello-world");
  request.Send();
  
  // wait for one response
  Response response = request.WaitForResponse();
```

There are 4 types of request: GET, POST, PUT, DELETE, defined as
`Method.GET`, `Method.POST`, `Method.PUT`, and `Method.DELETE`.

Responses can be received in two ways. By calling `request.WaitForResponse()`
a response will be received synchronously, which means it will 
block until timeout or a response is arrived. If more responses
are expected, call `WaitForResponse()` again.

To receive responses asynchronously, register a event handler to
the event `request.Respond` before executing.

> #### Parsing Link Format
Use `LinkFormat.Parse(String)` to parse a link-format
  response. The returned enumeration of `WebLink`
  contains all resources stated in the given link-format string.
  
```csharp
  Request request = new Request(Method.GET);
  request.URI = new Uri("coap://[::1]/.well-known/core");
  request.Send();
  Response response = request.WaitForResponse();
  IEnumerable<WebLink> links = LinkFormat.Parse(response.PayloadString);
```

See [CoAP Example Client](CoAP.Client) for more.

### CoAP Server
A new CoAP server can be easily built with help of the class
[**CoapServer**](CoAP.NET/Server/CoapServer.cs)

```csharp
  static void Main(String[] args)
  {
    CoapServer server = new CoapServer();
    
    server.Add(new HelloWorldResource("hello"));
    
    server.Start();
    
    Console.ReadKey();
  }
```

See [CoAP Example Server](CoAP.Server) for more.

### CoAP Resource
CoAP resources are classes that can be accessed by a URI via CoAP.
In CoAP.NET, a resource is defined as a subclass of [**Resource**](CoAP.NET/Server/Resources/Resource.cs).
By overriding methods `DoGet`, `DoPost`, `DoPut`, or `DoDelete`, one resource accepts
GET, POST, PUT or DELETE requests.

The following code gives an example of HelloWorldResource, which
can be visited by sending a GET request to "/hello-world", and
respones a plain string in code "2.05 Content".

```csharp
  class HelloWorldResource : Resource
  {
      public HelloWorldResource()
          : base("hello-world")
      {
          Attributes.Title = "GET a friendly greeting!";
      }

      protected override void DoGet(CoapExchange exchange)
      {
          exchange.Respond("Hello World from CoAP.NET!");
      }
  }
  
  class Server
  {
      static void Main(String[] args)
      {
          CoapServer server = new CoapServer();
          server.Add(new HelloWorldResource());
          server.Start();
      }
  }
```

See [CoAP Example Server](CoAP.Server) for more.

### Logging
Logging makes use of the [Microsoft.Extensions.Logging](https://www.nuget.org/packages/Microsoft.Extensions.Logging/) package.
Logging is configured using the static `LogManager` class.  By default, logs will be output to the console.  A custom logger 
can be specified by calling `LogManager.SetLoggerFactory(ILoggerFactory)` as follows:
```csharp
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddConsole();
});
LogManager.SetLoggerFactory(loggerFactory);
```


## Building the sources
TODO

## License
[BSD with attribution](https://spdx.org/licenses/BSD-3-Clause-Attribution.html)
See [LICENSE](LICENSE) for more info.

## Acknowledgements
This project is built on the [CoAP-CSharp](https://github.com/com-AugustCellars/CoAP-CSharp/) project of jimsch and the [CoAP.NET](https://github.com/smeshlink/CoAP.NET) 
project of smeshlink (which in turn is based on Eclipse Californium).  This is a refresh of the original codebases as they were both no longer being maintained.  
The package and class names have been reset to the original names per the CoAP.NET project.
