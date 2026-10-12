// Stop at the byte boundary even for chunked credential conversion responses.
export async function boundedText(response,limit=4*1024*1024){
 if(!response.body)return '';
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){void reader.cancel().catch(()=>{});throw Error('Upstream response exceeds limit');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 }finally{reader.releaseLock();}
}
