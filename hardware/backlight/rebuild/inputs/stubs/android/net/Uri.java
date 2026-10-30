package android.net;
public final class Uri { public final String value; public Uri(String value){this.value=value;} @Override public boolean equals(Object other){return other instanceof Uri && value.equals(((Uri)other).value);} @Override public int hashCode(){return value.hashCode();} }
