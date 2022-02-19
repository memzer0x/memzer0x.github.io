# Garbage
Garbage is the second challenge of the Flare-On 2021 reverse engineering event. It was quite a easy one to do and i really loved to solve this challenge.

With the challenge file (garbage.exe) we are given a message file (message.txt) which says the following.

```
One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted. We would fix it but we are too busy solving today's most important information security threats affecting our global economy. You should be able to get it working again, reverse engineer it, and acquire the flag.
```

This tells us that we are dealing with some corrupted binary and in order to obtain the flag, we need to try to fix the binary.

## Fixing the binary
To fix this binary we'll first open it in CFF Explorer so we can view and modify and properties of the file.

There's a couple of things to note about this binary before fixing it, let's check every part of our binaries for missing things.

![](https://i.imgur.com/3LBS2E8.png)

Looking at this first picture (this is the default window of CFF Explorer), we can notice a couple of things.
- PE Size is bigger than the File Size itself
- The file seemed to have been packed with UPX
- We are dealing with a 32bit binary

Trying to unpack this file with UPX gives us an error message that says the following.

![](https://i.imgur.com/wjQ8bqH.png)

**Invalid Overlay Size**, hmmmm... this looks like an error due to the **PE Size** being bigger than the **File Size** itself. 

Note that our PE Size is 41472 bytes, and our File Size is 40740 bytes, this mean in order to fix the problem with the file size we need to append 41742 - 40740 (732) bytes to the end of the file.

You can print 732 null bytes in IDLE Python using the following command :
`>> "00" * 732`

Then open your favorite hex editor and paste those bytes at the end of the file, don't forget to save and you can close that hex editor.

Reopening the binary in CFF Explorer shows that this time, the size of the file seems to be okay.

![](https://i.imgur.com/yKzodVF.png)

We can now try to unpack this file and see if we still get this **Overlay Size** error. (*note that you can unpack the file directly from CFF Explorer with their UPX Utility*)

![](https://i.imgur.com/IMH4xdI.png)

And we successfully unpacked the file, however if we try to execute it we still have this **side-by-side configuration** error...

Let's look deeper into the file.

When i opened the binary to append 732 null bytes to it, i noticed a strange truncated value at the end of our file (usually where .rsrc values are stored).

![](https://i.imgur.com/TDp38BJ.png)

It starts but it never ends, so in order to fix this part we will need to head over to our **Resource Editor** in CFF Explorer and delete this resource.

![](https://i.imgur.com/8oVtuwD.png)

Now if we try again to execute this file, we will still get this **side-by-side** configuration error, so it seems like we're not done fixing this binary.

Looking at the import directory, i can see that both modules have no names.

![](https://i.imgur.com/6Rohp8E.png)

We can fix this by putting the right names at the right place (Search for the Functions imported on google it should tell you which dlls they are using, with this you should be able to determine which module is which).

![](https://i.imgur.com/ZOKn68k.png)

Now save the binary and let's try to execute it.

![](https://i.imgur.com/kiamRcf.png)

AND THAT IS A FLAG BOOOYAAAAAAH !