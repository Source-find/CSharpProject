using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LogDiver.Core.Storage;

// System.Text.Json can't store an IPAddress by itself, so it is written as text like "203.0.113.5".
internal sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        IPAddress.TryParse(reader.GetString(), out var ip) ? ip : throw new JsonException("Not a valid IP address.");

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        writer.WriteStringValue(value.ToString());
    }
}
