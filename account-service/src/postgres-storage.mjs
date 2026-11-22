/** PostgreSQL adapter. The advisory transaction lock serializes all account mutations across isolates. */
export class PostgresStorage {
  constructor(sql){this.sql=sql;this.tx=null;}
  get query(){return this.tx||this.sql;}
  async locked(fn,shareOwner=null){
    if(this.tx)throw new Error('Nested account lock');
    return this.sql.begin(async tx=>{
      await tx`SET LOCAL lock_timeout = '12s'`;
      await tx`SET LOCAL statement_timeout = '25s'`;
      if(shareOwner!==null)await tx`SELECT pg_advisory_xact_lock(1935764578, hashtext(${shareOwner}))`;
      else await tx`SELECT pg_advisory_xact_lock(1935764577, 1)`;
      this.tx=tx;
      try{return await fn();}finally{this.tx=null;}
    });
  }
  async get(key){const rows=await this.query`SELECT value FROM salam_private.state WHERE key=${key}`;return rows[0]?.value;}
  async put(key,value){const sql=this.query;await sql`INSERT INTO salam_private.state(key,value) VALUES(${key},${sql.json(value)}) ON CONFLICT(key) DO UPDATE SET value=excluded.value`;}
  async delete(keys){const list=Array.isArray(keys)?keys:[keys];if(list.length)await this.query`DELETE FROM salam_private.state WHERE key=ANY(${list}::text[])`;}
  async list({prefix='',limit=1000,after=''}={}){
    const pattern=prefix.replace(/[\\%_]/g,'\\$&')+'%';
    const rows=await this.query`SELECT key,value FROM salam_private.state WHERE key LIKE ${pattern} AND key>${after} ORDER BY key LIMIT ${limit}`;
    return new Map(rows.map(r=>[r.key,r.value]));
  }
  transaction(fn){return this.tx?fn(this):this.locked(()=>fn(this));}
  sharingTransaction(fn,owner){return this.locked(fn,owner);}
  async shareLimit(key,max,window,now){
    const sql=this.query,value={count:1,until:now+window};
    const rows=await sql`INSERT INTO salam_private.state(key,value) VALUES(${key},${sql.json(value)})
      ON CONFLICT(key) DO UPDATE SET value=CASE WHEN (state.value->>'until')::bigint<=${now}
        THEN excluded.value ELSE jsonb_set(state.value,'{count}',to_jsonb((state.value->>'count')::int+1)) END
      WHERE (state.value->>'until')::bigint<=${now} OR (state.value->>'count')::int<${max} RETURNING key`;
    return rows.length>0;
  }
  async reserveShare(key,value,now){
    const sql=this.query;
    const rows=await sql`INSERT INTO salam_private.state(key,value) VALUES(${key},${sql.json(value)})
      ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE (state.value->>'until')::bigint<=${now} RETURNING key`;
    return rows.length>0;
  }
  getAlarm(){return this.get('$alarm');}setAlarm(time){return this.put('$alarm',time);}deleteAlarm(){return this.delete('$alarm');}
}
