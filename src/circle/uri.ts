export class OctUri {
  readonly circleId: string;
  readonly path: string;

  constructor(circleId: string, path = "/index.html") {
    this.circleId = circleId;
    this.path = path.startsWith("/") ? path : `/${path}`;
  }

  static parse(uri: string): OctUri {
    if (!uri.startsWith("oct://")) throw new Error(`Invalid oct:// URI: "${uri}"`);
    const rest = uri.slice(6);
    const slash = rest.indexOf("/");
    if (slash < 0) return new OctUri(rest, "/index.html");
    return new OctUri(rest.slice(0, slash), rest.slice(slash) || "/index.html");
  }

  toString(): string {
    return `oct://${this.circleId}${this.path}`;
  }
}
