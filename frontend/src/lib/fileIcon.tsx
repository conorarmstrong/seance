import {
  File,
  FileText,
  FileImage,
  FileVideo,
  FileAudio,
  FileSpreadsheet,
  FileArchive,
  FileCode,
  type LucideIcon,
} from 'lucide-react'

const BY_EXT: Record<string, LucideIcon> = {}
const map = (icon: LucideIcon, exts: string[]) => {
  for (const e of exts) BY_EXT[e] = icon
}
map(FileImage, ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp', 'heic', 'ico'])
map(FileVideo, ['mp4', 'mov', 'wmv', 'avi', 'mkv', 'm4v', 'webm', 'flv', 'mpg', 'mpeg'])
map(FileAudio, ['mp3', 'wav', 'flac', 'ogg', 'm4a', 'aac', 'wma'])
map(FileSpreadsheet, ['xls', 'xlsx', 'csv', 'ods', 'tsv'])
map(FileArchive, ['zip', 'rar', '7z', 'gz', 'tar', 'bz2', 'xz', 'cab'])
map(FileCode, ['json', 'xml', 'html', 'htm', 'js', 'ts', 'tsx', 'py', 'rs', 'c', 'cpp', 'h', 'sh', 'sql', 'yaml', 'yml'])
map(FileText, ['txt', 'md', 'log', 'doc', 'docx', 'rtf', 'odt', 'pdf', 'ppt', 'pptx'])

/** lucide icon component for a filename, chosen by extension; generic fallback. */
export function iconForName(name?: string | null): LucideIcon {
  const ext = name?.split('.').pop()?.toLowerCase() ?? ''
  return BY_EXT[ext] ?? File
}
