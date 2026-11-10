import { CircuitLogo } from './components/CircuitLogo';
import {useEffect} from 'react';

export function WorkspaceIntro({onComplete}:{onComplete:()=>void}){
  useEffect(()=>{
    const timeout=window.setTimeout(onComplete,4500);
    return ()=>window.clearTimeout(timeout);
  },[onComplete]);

  return (
    <main className="workspace-intro" aria-label="Workspace startup">
      <div className="entry-stage">
        <div className="entry-halo" aria-hidden="true"/>
        <div className="entry-orbit" aria-hidden="true"/>
        <div className="entry-orbit entry-orbit-inner" aria-hidden="true"/>
        <CircuitLogo className="entry-logo" />
      </div>
      <p className="entry-caption" role="status">Opening your security workspace…</p>
      <span className="entry-ready" aria-hidden="true">WORKSPACE READY</span>
      <div className="entry-track" aria-hidden="true" onAnimationEnd={onComplete}/>
    </main>
  );
}
