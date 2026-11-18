"""Allocate a new immutable desktop release, including explicit candidate versions."""
import argparse
import re
from pathlib import Path


def parsed(value):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):
        raise ValueError('Invalid release version')
    parts=tuple(map(int,value.split('.')))
    if max(parts)>2147483647:raise ValueError('Release version out of range')
    return parts


def choose(requested,run_number,files):
    if type(run_number) is not int or not 0<run_number<2147483547:raise ValueError('Invalid run number')
    versions=[]
    for name in files:
        match=re.fullmatch(r'(?:candidates/)?(?:latest|reserved)-([0-9]+\.[0-9]+\.[0-9]+)\.json',name.strip())
        if match:versions.append(parsed(match[1]))
    current=max(versions,default=(1,0,0))
    if requested:
        target=parsed(requested)
        if target<=current:raise ValueError('Release version already used or older than a candidate')
    else:
        if current[:2]>(1,0):raise ValueError('Explicit version required for the new release series')
        target=(1,0,max(run_number+100,current[2]+1))
    return '.'.join(map(str,target))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--requested',default='');p.add_argument('--run-number',type=int,required=True);p.add_argument('--files',type=Path,required=True);a=p.parse_args()
    if a.files.stat().st_size>1024*1024:raise SystemExit('Release inventory too large')
    print(choose(a.requested,a.run_number,a.files.read_text().splitlines()))
