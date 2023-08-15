using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

const string cookieName = "my_auth";

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Events.OnRedirectToLogin = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            
            return Task.CompletedTask;
        };
        
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.Name = cookieName;
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseCookiePolicy();
app.UseAuthorization();

app.UseStaticFiles(new StaticFileOptions
{
    RequestPath = "",
    FileProvider = new PhysicalFileProvider(Path.Join(Environment.CurrentDirectory, "static")),
});

app.MapGet("/", () => Results.Redirect("/index.html"));

app.MapGet("/some-data", (HttpContext context) =>
{
    if (context.Request.Cookies.TryGetValue(cookieName, out var cookie))
    {
        
    }
    return "Hello World!";
}).RequireAuthorization();

app.MapGet("/generate-pdf", async (HttpContext context) =>
{
    var waitFor = ChromePdfRenderOptions.DefaultChrome.WaitFor;
    waitFor.JavaScript();
    var myCookie = context.Request.Cookies[cookieName]!;
    var renderer = new ChromePdfRenderer
    {
        LoginCredentials = new ChromeHttpLoginCredentials
        {
            CustomCookies = new Dictionary<string, string>
            {
                {cookieName, myCookie}
            }
        },
        RenderingOptions = new ChromePdfRenderOptions
        {
            WaitFor = waitFor,
        }
    };

    var pdf = await renderer.RenderUrlAsPdfAsync("http://localhost:5500/index.html");

    return Results.File(pdf.Stream, "application/pdf");
}).RequireAuthorization();

app.MapGet("/login", async (IAuthenticationService authenticationService, HttpContext context) =>
{
    var claims = new List<Claim>
    {
        new (ClaimTypes.Email, "test@example.com"),
        new (ClaimTypes.Role, "Admin")
    };
    
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme,
        ClaimTypes.Email, ClaimTypes.Role);
    var principal = new ClaimsPrincipal(identity);
    await authenticationService.SignInAsync(context, CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties());

    return Results.Ok();
}).AllowAnonymous();

app.Run();