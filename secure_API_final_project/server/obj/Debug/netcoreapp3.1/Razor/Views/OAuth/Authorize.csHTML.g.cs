#pragma checksum "C:\Users\sanam\source\repos\secure_API_final_project\server\Views\OAuth\Authorize.csHTML" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "abcf0601f2001ebf9d5ed201804949fe4d2e07b7"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_OAuth_Authorize), @"mvc.1.0.view", @"/Views/OAuth/Authorize.csHTML")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"abcf0601f2001ebf9d5ed201804949fe4d2e07b7", @"/Views/OAuth/Authorize.csHTML")]
    public class Views_OAuth_Authorize : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<string>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 3 "C:\Users\sanam\source\repos\secure_API_final_project\server\Views\OAuth\Authorize.csHTML"
   
    var url = $"/OAuth/Authorize{Model}";

#line default
#line hidden
#nullable disable
            WriteLiteral("<form");
            BeginWriteAttribute("action", " action=\"", 73, "\"", 86, 1);
#nullable restore
#line 6 "C:\Users\sanam\source\repos\secure_API_final_project\server\Views\OAuth\Authorize.csHTML"
WriteAttributeValue("", 82, url, 82, 4, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" method=\"post\">\r\n    <input type=\"text\" name=\"username\"");
            BeginWriteAttribute("value", " value=\"", 142, "\"", 150, 0);
            EndWriteAttribute();
            WriteLiteral("/>\r\n    <input type=\"submit\" value=\" submit\"/>\r\n</form>");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<string> Html { get; private set; }
    }
}
#pragma warning restore 1591
