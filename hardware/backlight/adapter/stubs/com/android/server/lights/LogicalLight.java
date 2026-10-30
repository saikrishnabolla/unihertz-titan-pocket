package com.android.server.lights;
public abstract class LogicalLight {public abstract void setBrightness(float brightness);public abstract void setColor(int color);public abstract void setFlashing(int color,int mode,int on,int off);public abstract void turnOff();}
