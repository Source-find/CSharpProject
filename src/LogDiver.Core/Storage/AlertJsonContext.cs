using System.Text.Json.Serialization;
using LogDiver.Core.Detection;

namespace LogDiver.Core.Storage;

// Source-generated JSON: the code that reads and writes an Alert is created at build time instead of
// being worked out with reflection at runtime, which is faster and uses less memory.
// Enums are stored as text ("High" instead of 2) and names in camelCase ("ruleName").
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true,
    Converters = new[] { typeof(IPAddressJsonConverter) })]
[JsonSerializable(typeof(Alert))]
internal sealed partial class AlertJsonContext : JsonSerializerContext
{
}
