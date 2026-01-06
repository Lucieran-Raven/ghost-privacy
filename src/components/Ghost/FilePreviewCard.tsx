import { FileText, FileSpreadsheet, FileImage, FileArchive, FileCode, File, Download } from 'lucide-react';
import { cn } from '@/lib/utils';
import { sanitizeFileName, getFileIconType } from '@/utils/security';
import { useEffect, useState } from 'react';

interface FilePreviewCardProps {
  fileName: string;
  content: string;
  sender: 'me' | 'partner';
}

const FilePreviewCard = ({ fileName, content, sender }: FilePreviewCardProps) => {
  const safeName = sanitizeFileName(fileName);
  const iconType = getFileIconType(safeName);
  const extension = safeName.split('.').pop()?.toUpperCase() || 'FILE';
  const [{ objectUrl, shouldRevoke }] = useState(() => {
    try {
      if (content.startsWith('data:')) {
        return { objectUrl: content, shouldRevoke: false };
      }
      if (content.startsWith('blob:')) {
        return { objectUrl: content, shouldRevoke: false };
      }
      const url = URL.createObjectURL(new Blob([content]));
      return { objectUrl: url, shouldRevoke: true };
    } catch {
      return { objectUrl: content, shouldRevoke: false };
    }
  });

  useEffect(() => {
    return () => {
      if (shouldRevoke) {
        try {
          URL.revokeObjectURL(objectUrl);
        } catch {
          // Ignore
        }
      }
    };
  }, [objectUrl, shouldRevoke]);

  // Check if content is an image or video
  const isImage = iconType === 'image' || safeName.match(/\.(jpg|jpeg|png|gif|webp)$/i);
  const isVideo = safeName.match(/\.(mp4|webm|mov)$/i);
  const isLink = content.startsWith('http://') || content.startsWith('https://');

  
  // Estimate file size from base64 content
  const base64Length = content.split(',')[1]?.length || content.length;
  const estimatedSize = content.startsWith('data:') 
    ? Math.round((base64Length * 3) / 4)
    : content.startsWith('blob:')
      ? null
      : base64Length;
  const formattedSize = estimatedSize === null
    ? 'Unknown'
    : estimatedSize < 1024 
      ? `${estimatedSize} B` 
      : estimatedSize < 1024 * 1024 
        ? `${(estimatedSize / 1024).toFixed(1)} KB`
        : `${(estimatedSize / (1024 * 1024)).toFixed(2)} MB`;
  
  const handleDownload = (e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation();
    }
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = safeName;
    link.click();
  };
  
  const IconComponent = {
    pdf: FileText,
    doc: FileText,
    spreadsheet: FileSpreadsheet,
    image: FileImage,
    archive: FileArchive,
    code: FileCode,
    generic: File
  }[iconType];

  const iconColors = {
    pdf: 'text-red-400',
    doc: 'text-blue-400',
    spreadsheet: 'text-green-400',
    image: 'text-purple-400',
    archive: 'text-yellow-400',
    code: 'text-cyan-400',
    generic: 'text-muted-foreground'
  };

  // Link preview
  if (isLink) {
    try {
      const url = new URL(content);
      return (
        <div className={cn(
          "p-4 rounded-xl border",
          sender === 'me' 
            ? "bg-primary/10 border-primary/30" 
            : "bg-secondary/50 border-border/50"
        )}>
          <a 
            href={content} 
            target="_blank" 
            rel="noopener noreferrer"
            className="block"
          >
            <p className={cn(
              "text-sm font-medium mb-1",
              sender === 'me' ? "text-primary-foreground" : "text-foreground"
            )}>
              {url.hostname}
            </p>
            <p className={cn(
              "text-xs",
              sender === 'me' ? "text-primary-foreground/60" : "text-muted-foreground"
            )}>
              Click to open link
            </p>
          </a>
        </div>
      );
    } catch {
      // Invalid URL, fall through to file preview
    }
  }

  // Image preview
  if (isImage && (content.startsWith('data:image') || content.startsWith('blob:'))) {
    return (
      <div className={cn(
        "relative rounded-xl overflow-hidden",
        sender === 'me' 
          ? "bg-primary/10 border border-primary/30" 
          : "bg-secondary/50 border border-border/50"
      )}>
        <img 
          src={objectUrl} 
          alt={safeName}
          className="w-full h-auto max-h-96 object-contain"
        />
        <button
          onClick={handleDownload}
          className={cn(
            "absolute top-2 right-2 p-2 rounded-full backdrop-blur-sm transition-all",
            sender === 'me' 
              ? "bg-black/70 hover:bg-black/80 text-white" 
              : "bg-black/70 hover:bg-black/80 text-white"
          )}
          aria-label="Download image"
          title="Download image"
        >
          <Download className="h-4 w-4" />
        </button>
        {safeName && (
          <div className={cn(
            "absolute bottom-0 left-0 right-0 p-2 bg-gradient-to-t from-black/80 to-transparent"
          )}>
            <p className={cn(
              "text-xs truncate text-white",
            )}>
              {safeName}
            </p>
          </div>
        )}
      </div>
    );
  }

  // Video preview
  if (isVideo && (content.startsWith('data:video') || content.startsWith('blob:'))) {
    return (
      <div className={cn(
        "relative rounded-xl overflow-hidden",
        sender === 'me' 
          ? "bg-primary/10 border border-primary/30" 
          : "bg-secondary/50 border border-border/50"
      )}>
        <video 
          controls
          className="w-full h-auto max-h-96"
          preload="metadata"
        >
          <source src={objectUrl} type={`video/${extension.toLowerCase()}`} />
          Your browser does not support video playback.
        </video>
        <button
          onClick={handleDownload}
          className={cn(
            "absolute top-2 right-2 p-2 rounded-full backdrop-blur-sm transition-all",
            "bg-black/70 hover:bg-black/80 text-white"
          )}
          aria-label="Download video"
          title="Download video"
        >
          <Download className="h-4 w-4" />
        </button>
        {safeName && (
          <div className={cn(
            "absolute bottom-0 left-0 right-0 p-2 bg-gradient-to-t from-black/80 to-transparent"
          )}>
            <p className={cn(
              "text-xs truncate text-white",
            )}>
              {safeName}
            </p>
          </div>
        )}
      </div>
    );
  }

  // Default file preview
  return (
    <div 
      className={cn(
        "file-preview-mobile cursor-pointer transition-all active:scale-[0.98]",
        sender === 'me' 
          ? "bg-primary/10 border border-primary/30 active:border-primary/50" 
          : "bg-secondary/50 border border-border/50 active:border-border"
      )}
      onClick={handleDownload}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && handleDownload()}
    >
      <div className="flex items-center gap-3">
        <div className={cn(
          "p-2.5 rounded-xl flex-shrink-0",
          sender === 'me' ? "bg-primary/20" : "bg-secondary"
        )}>
          <IconComponent className={cn("h-6 w-6", iconColors[iconType])} />
        </div>
        
        <div className="flex-1 min-w-0">
          <p className={cn(
            "text-sm font-medium truncate",
            sender === 'me' ? "text-primary-foreground" : "text-foreground"
          )}>
            {safeName}
          </p>
          <div className={cn(
            "flex items-center gap-2 text-xs mt-0.5",
            sender === 'me' ? "text-primary-foreground/60" : "text-muted-foreground"
          )}>
            <span>{extension}</span>
            <span>•</span>
            <span>{formattedSize}</span>
          </div>
        </div>
        
        <Download className={cn(
          "h-5 w-5 flex-shrink-0",
          sender === 'me' ? "text-primary-foreground/50" : "text-muted-foreground/60"
        )} />
      </div>
      
      <p className={cn(
        "text-[10px] mt-2 uppercase tracking-wide",
        sender === 'me' ? "text-primary-foreground/40" : "text-muted-foreground/50"
      )}>
        Tap to download • E2E Encrypted
      </p>
    </div>
  );
};

export default FilePreviewCard;